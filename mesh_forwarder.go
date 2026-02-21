package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ztunnel/Istio ambient mesh ports
const (
	ZtunnelInboundPort  = 15008 // HBONE tunnel port
	ZtunnelOutboundPort = 15001 // Envoy outbound
	ZtunnelInboundPlain = 15006 // Inbound plaintext
	ZtunnelMetricsPort  = 15020 // Metrics
	ZtunnelHealthPort   = 15021 // Health check
)

// MeshConnectionEvent represents a service mesh connection event
type MeshConnectionEvent struct {
	ClusterID       string    `json:"cluster_id"`
	Timestamp       time.Time `json:"timestamp"`
	SourceNamespace string    `json:"source_namespace"`
	SourcePod       string    `json:"source_pod"`
	SourceSPIFFE    string    `json:"source_spiffe"`
	DestNamespace   string    `json:"dest_namespace"`
	DestPod         string    `json:"dest_pod"`
	DestSPIFFE      string    `json:"dest_spiffe"`
	DestHostname    string    `json:"dest_hostname,omitempty"` // For external: google.com, dns.google, etc.
	DestPort        int       `json:"dest_port"`
	Protocol        string    `json:"protocol"`
	BytesSent       int64     `json:"bytes_sent"`
	BytesReceived   int64     `json:"bytes_received"`
	DurationMs      int64     `json:"duration_ms"`
	TLSVersion      string    `json:"tls_version"`
	Status          string    `json:"connection_status"` // success, denied, failed
	SourceIP        string    `json:"source_ip"`
	DestIP          string    `json:"dest_ip"`
}

// MeshForwarder handles forwarding mesh connection events to the backend
type MeshForwarder struct {
	endpoint     string
	meshEndpoint string // When set, use directly; else derive from endpoint
	token        string
	clusterID    string
	orgID        uint
	client       *http.Client
	eventBuffer  []MeshConnectionEvent
	bufferMu     sync.Mutex
	flushTicker  *time.Ticker
	podCache     *PodCache
	dnsCache     *DNSCache // IP -> hostname for external destinations (reverse lookup)
	logger       *log.Logger
	enabled      bool
	captureAll   bool   // Capture all TCP connections, not just ztunnel ports
	procRoot     string // Root for /proc (e.g. /host/proc when host proc is mounted there)
	k8sClient    kubernetes.Interface
	natsConn     *nats.Conn
	natsSubject  string // e.g. mesh.connections
}

// DNSCache caches reverse DNS lookups for external IPs (IP -> hostname)
type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]string
}

// PodCache caches pod IP to namespace/name mappings
type PodCache struct {
	mu       sync.RWMutex
	cache    map[string]PodInfo // keyed by IP
	uidCache map[string]PodInfo // keyed by pod UID
	pidCache map[uint32]PodInfo // keyed by PID — survives short-lived processes
	pidMu    sync.RWMutex
}

// PodInfo holds pod metadata
type PodInfo struct {
	Namespace      string
	Name           string
	ServiceAccount string
	LastSeen       time.Time
}

// NewMeshForwarder creates a new mesh event forwarder
func NewMeshForwarder(cfg Config, logger *log.Logger) *MeshForwarder {
	mf := &MeshForwarder{
		endpoint:     cfg.Endpoint,
		meshEndpoint: cfg.MeshEndpoint,
		token:        cfg.Token,
		clusterID:   cfg.ClusterID,
		orgID:       cfg.OrgID,
		client:      &http.Client{Timeout: 10 * time.Second},
		eventBuffer: make([]MeshConnectionEvent, 0, 100),
		flushTicker: time.NewTicker(5 * time.Second),
		podCache:    &PodCache{cache: make(map[string]PodInfo), uidCache: make(map[string]PodInfo), pidCache: make(map[uint32]PodInfo)},
		logger:      logger,
		enabled:     cfg.MeshEnabled,
		captureAll:  cfg.MeshCaptureAll,
		procRoot:    cfg.ProcRoot,
	}
	if mf.procRoot == "" {
		mf.procRoot = "/proc"
	}

	// Try to create Kubernetes client for pod lookups
	k8sConfig, err := rest.InClusterConfig()
	if err != nil {
		logger.Printf("Warning: cannot create in-cluster k8s config: %v (pod lookups will be limited)", err)
	} else {
		k8sClient, err := kubernetes.NewForConfig(k8sConfig)
		if err != nil {
			logger.Printf("Warning: cannot create k8s client: %v (pod lookups will be limited)", err)
		} else {
			mf.k8sClient = k8sClient
			logger.Println("Kubernetes client initialized for pod lookups")
		}
	}

	mf.dnsCache = &DNSCache{cache: make(map[string]string)}

	// Optional NATS publish for mesh events (backend subscribes to mesh.connections)
	if natsURL := strings.TrimSpace(os.Getenv("NATS_URL")); natsURL != "" {
		subject := strings.TrimSpace(os.Getenv("NATS_MESH_SUBJECT"))
		if subject == "" {
			subject = "mesh.connections"
		}
		nc, err := nats.Connect(natsURL, nats.Name("prysm-ebpf-mesh"), nats.MaxReconnects(-1),
			nats.ReconnectWait(2*time.Second))
		if err != nil {
			logger.Printf("Warning: NATS connect failed: %v (mesh events will use HTTP only)", err)
		} else {
			mf.natsConn = nc
			mf.natsSubject = subject
			logger.Printf("Mesh forwarder: NATS publish enabled → %s", subject)
		}
	}

	return mf
}

// Start begins the mesh forwarder background processes
func (mf *MeshForwarder) Start(ctx context.Context) {
	if !mf.enabled {
		mf.logger.Println("Mesh forwarder disabled")
		return
	}

	// Pre-populate pod cache synchronously before starting
	mf.refreshPodCacheFromK8s(ctx)

	meshURL := mf.meshEndpoint
	if meshURL == "" {
		meshURL = mf.endpoint + "/agent/ztunnel/events"
	}
	mf.logger.Printf("🔒 Mesh forwarder started → %s (token=%v cluster=%s)",
		meshURL, mf.token != "", mf.clusterID)
	if mf.captureAll {
		mf.logger.Printf("   Capture: ALL TCP connections")
	} else {
		mf.logger.Printf("   Capture: ztunnel ports only")
	}

	// Start periodic flush
	go mf.flushLoop(ctx)

	// Start pod cache refresh
	go mf.refreshPodCache(ctx)
}

// flushLoop periodically sends buffered events to the backend
func (mf *MeshForwarder) flushLoop(ctx context.Context) {
	tick := 0
	for {
		select {
		case <-ctx.Done():
			mf.flush() // Final flush
			return
		case <-mf.flushTicker.C:
			mf.flush()
			tick++
			// Every 12 ticks (~60s), log mesh stats when we have events (helps debug "0 in store")
			if tick%12 == 0 {
				mf.bufferMu.Lock()
				n := len(mf.eventBuffer)
				mf.bufferMu.Unlock()
				if n > 0 {
					mf.logger.Printf("mesh: %d events buffered (waiting for flush)", n)
				}
			}
		}
	}
}

// flush sends all buffered events to the backend
func (mf *MeshForwarder) flush() {
	mf.bufferMu.Lock()
	if len(mf.eventBuffer) == 0 {
		mf.bufferMu.Unlock()
		return
	}

	events := mf.eventBuffer
	mf.eventBuffer = make([]MeshConnectionEvent, 0, 100)
	mf.bufferMu.Unlock()

	if err := mf.sendEvents(events); err != nil {
		mf.logger.Printf("Failed to send mesh events: %v", err)
	}
}

// sendEvents sends a batch of mesh events to the backend
func (mf *MeshForwarder) sendEvents(events []MeshConnectionEvent) error {
	if mf.endpoint == "" || mf.token == "" {
		mf.logger.Printf("Mesh events skipped: endpoint or token not configured (endpoint=%q)", mf.endpoint)
		return nil
	}

	payload := map[string]interface{}{
		"organization_id": mf.orgID,
		"cluster_id":      mf.clusterID,
		"events":         events,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	meshEndpoint := mf.meshEndpoint
	if meshEndpoint == "" {
		// Derive from log endpoint: replace /logs/ingest with /agent/ztunnel/events
		meshEndpoint = mf.endpoint
		if len(meshEndpoint) > 12 && meshEndpoint[len(meshEndpoint)-12:] == "/logs/ingest" {
			meshEndpoint = meshEndpoint[:len(meshEndpoint)-12] + "/agent/ztunnel/events"
		} else {
			meshEndpoint = meshEndpoint + "/agent/ztunnel/events"
		}
	}

	req, err := http.NewRequest("POST", meshEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mf.token)
	req.Header.Set("X-Cluster-ID", mf.clusterID)

	resp, err := mf.client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		if len(body) > 200 {
			body = body[:200]
		}
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
	}

	// NOTE: NATS publish removed to avoid duplicate processing.
	// Events are sent via HTTP; backend no longer needs dual-path ingestion.

	mf.logger.Printf("📤 Sent %d mesh events to backend", len(events))
	return nil
}

// ProcessSecurityEvent checks if a security event is mesh-related and forwards it.
// Always returns true for network events to prevent them from saturating the shared
// eventChan (they're high-volume and the shared channel is already flooded by syscall events).
func (mf *MeshForwarder) ProcessSecurityEvent(event SecurityEvent) bool {
	if !mf.enabled {
		return false
	}

	// Only process network connect events
	if event.EventType != EventNetworkConnect {
		return false
	}

	// Early exit for events with no useful data (e.g., from trace_udp_send which
	// provides no address/port info, or trace_tcp_v6_connect with unresolved fields).
	// These are high-volume noise that waste CPU in pod resolution.
	dstPort := extractDstPort(event)
	if dstPort == 0 {
		return true // consume the event to keep it out of the shared channel
	}

	srcPort := extractSrcPort(event)
	protocol := extractProtocol(event)

	// Process: ztunnel ports, captureAll, or UDP DNS (port 53) for mesh topology
	isUDPDNS := protocol == "UDP" && dstPort == 53
	if !mf.captureAll && !isZtunnelPort(dstPort) && !isZtunnelPort(srcPort) && !isUDPDNS {
		return true // consume but don't process
	}

	// Convert to mesh event (returns false if pods can't be resolved)
	meshEvent, ok := mf.convertToMeshEvent(event)
	if !ok {
		return true // consume but don't buffer
	}

	// Buffer the event
	mf.bufferMu.Lock()
	mf.eventBuffer = append(mf.eventBuffer, meshEvent)

	// Flush if buffer is getting large
	if len(mf.eventBuffer) >= 50 {
		events := mf.eventBuffer
		mf.eventBuffer = make([]MeshConnectionEvent, 0, 100)
		mf.bufferMu.Unlock()
		go func() {
			if err := mf.sendEvents(events); err != nil {
				mf.logger.Printf("Failed to send mesh events: %v", err)
			}
		}()
	} else {
		mf.bufferMu.Unlock()
	}

	return true
}

// convertToMeshEvent converts a SecurityEvent to a MeshConnectionEvent.
// Returns false if source or destination pod cannot be resolved from the cache,
// since synthetic "unknown" entries pollute the topology view.
func (mf *MeshForwarder) convertToMeshEvent(event SecurityEvent) (MeshConnectionEvent, bool) {
	// IPv4 addresses are stored as little-endian uint32 in the first 4 bytes of the 16-byte addr fields
	srcIP := extractIPv4FromLittleEndian(event.Data.Raw[12:16]) // src_addr starts at offset 12
	dstIP := extractIPv4FromLittleEndian(event.Data.Raw[28:32]) // dst_addr starts at offset 28
	dstPort := extractDstPort(event)
	srcPort := extractSrcPort(event)

	// Look up pod info from cache
	srcPod := mf.podCache.GetPodInfo(srcIP)
	dstPod := mf.podCache.GetPodInfo(dstIP)

	// If IP lookup failed (IP is 0.0.0.0), try PID-based lookup for source
	if srcIP == "0.0.0.0" || srcPod.Namespace == "" {
		srcPod = mf.getPodInfoByPID(event.PID)
	}

	// DEBUG: log resolution results for first few events
	mf.logConvertDebug2(srcIP, dstIP, dstPort, srcPort, event, srcPod, dstPod)

	// DEBUG: always log cluster-IP connections (temporary, to verify demo-app events are captured)
	if strings.HasPrefix(dstIP, "10.42.") || strings.HasPrefix(dstIP, "10.43.") {
		comm := extractComm(event.Comm[:])
		// Extra debug for source resolution: try reading cgroup directly
		pidDebug := ""
		cgroupPath := filepath.Join(mf.procRoot, fmt.Sprintf("%d", event.PID), "cgroup")
		if cgData, err := os.ReadFile(cgroupPath); err != nil {
			pidDebug = fmt.Sprintf("proc-err=%v", err)
		} else {
			uid := extractPodUIDFromCgroup(string(cgData))
			podInfo := mf.podCache.GetPodInfoByUID(uid)
			pidDebug = fmt.Sprintf("uid=%s pod=%s/%s", uid, podInfo.Namespace, podInfo.Name)
		}
		bytesSent := extractBytesSent(event)
		bytesRecv := extractBytesReceived(event)
		eventKind := "connect"
		if event.SecurityLevel == SecurityLevelMedium {
			eventKind = "close"
		}
		mf.logger.Printf("mesh-cluster: [%s] comm=%s pid=%d srcIP=%s dstIP=%s dstPort=%d src=%s/%s dst=%s/%s sent=%d recv=%d [%s]",
			eventKind, comm, event.PID, srcIP, dstIP, dstPort,
			srcPod.Namespace, srcPod.Name, dstPod.Namespace, dstPod.Name, bytesSent, bytesRecv, pidDebug)
	}

	// Source must be a pod (we need to know which pod initiated)
	if srcPod.Name == "" || srcPod.Namespace == "" {
		return MeshConnectionEvent{}, false
	}

	destNamespace := dstPod.Namespace
	destPod := dstPod.Name
	destSPIFFE := buildSPIFFE(mf.orgID, mf.clusterID, dstPod)
	destHostname := ""

	if dstPod.Name == "" || dstPod.Namespace == "" {
		// External destination (pod egress: curl -> google.com)
		if !isExternalIP(dstIP) {
			return MeshConnectionEvent{}, false // Skip non-cluster IPs we can't resolve (e.g. 0.0.0.0)
		}
		destNamespace = "external"
		destPod = dstIP
		destSPIFFE = ""
		// Resolve hostname via reverse DNS (cached)
		destHostname = mf.dnsCache.GetOrLookup(dstIP)
		if destHostname != "" {
			destPod = destHostname // Prefer hostname for display (e.g. google.com)
		}
		// For DNS traffic (port 53), label as dns
		if dstPort == 53 && destHostname == "" {
			destPod = dstIP + ":53"
		}
	}

	// Determine TLS version: only ztunnel ports use TLS 1.3
	tlsVersion := ""
	if isZtunnelPort(dstPort) || isZtunnelPort(srcPort) {
		tlsVersion = "TLSv1.3" // ztunnel uses TLS 1.3
	}

	meshEvent := MeshConnectionEvent{
		ClusterID:       mf.clusterID,
		Timestamp:       time.Now(),
		SourceNamespace: srcPod.Namespace,
		SourcePod:       srcPod.Name,
		SourceSPIFFE:    buildSPIFFE(mf.orgID, mf.clusterID, srcPod),
		DestNamespace:   destNamespace,
		DestPod:         destPod,
		DestSPIFFE:      destSPIFFE,
		DestHostname:    destHostname,
		DestPort:        int(dstPort),
		Protocol:        extractProtocol(event),
		BytesSent:       extractBytesSent(event),
		BytesReceived:   extractBytesReceived(event),
		DurationMs:      0,
		TLSVersion:      tlsVersion,
		Status:          "success",
		SourceIP:        srcIP,
		DestIP:          dstIP,
	}

	return meshEvent, true
}

// refreshPodCache periodically refreshes the pod IP cache from Kubernetes API
func (mf *MeshForwarder) refreshPodCache(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			mf.refreshPodCacheFromK8s(ctx)
			mf.podCache.Cleanup()
		}
	}
}

// refreshPodCacheFromK8s queries Kubernetes API for all pod and service IPs
func (mf *MeshForwarder) refreshPodCacheFromK8s(ctx context.Context) {
	if mf.k8sClient == nil {
		return
	}

	pods, err := mf.k8sClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		mf.logger.Printf("Failed to list pods: %v", err)
		return
	}

	count := 0
	for _, pod := range pods.Items {
		info := PodInfo{
			Namespace:      pod.Namespace,
			Name:           pod.Name,
			ServiceAccount: pod.Spec.ServiceAccountName,
			LastSeen:       time.Now(),
		}
		// Cache by IP if available
		if pod.Status.PodIP != "" {
			mf.podCache.SetPodInfo(pod.Status.PodIP, info)
		}
		// Also cache by UID for PID-based lookups
		if string(pod.UID) != "" {
			mf.podCache.SetPodInfoByUID(string(pod.UID), info)
		}
		count++
	}

	// Also cache service ClusterIPs so connections via kube-proxy DNAT can be resolved.
	// Applications connect to ClusterIPs; the eBPF kprobe captures these before DNAT.
	svcCount := 0
	services, err := mf.k8sClient.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		mf.logger.Printf("Failed to list services: %v", err)
	} else {
		for _, svc := range services.Items {
			if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
				continue
			}
			info := PodInfo{
				Namespace: svc.Namespace,
				Name:      svc.Name,
				LastSeen:  time.Now(),
			}
			mf.podCache.SetPodInfo(svc.Spec.ClusterIP, info)
			svcCount++
		}
	}

	mf.logger.Printf("Refreshed pod cache: %d pods, %d services", count, svcCount)

	// Proactively build PID → pod mapping by scanning /proc/<pid>/cgroup.
	// This must run AFTER the UID cache is populated so we can resolve UIDs to pods.
	pidCount := mf.refreshPIDCache()
	if pidCount > 0 {
		mf.logger.Printf("Refreshed PID cache: %d PIDs mapped to pods", pidCount)
	}
}

// GetPodInfo retrieves pod info for an IP
func (pc *PodCache) GetPodInfo(ip string) PodInfo {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	if info, ok := pc.cache[ip]; ok {
		return info
	}
	return PodInfo{}
}

// SetPodInfo updates pod info for an IP
func (pc *PodCache) SetPodInfo(ip string, info PodInfo) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	info.LastSeen = time.Now()
	pc.cache[ip] = info
}

// SetPodInfoByUID updates pod info for a pod UID
func (pc *PodCache) SetPodInfoByUID(uid string, info PodInfo) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	info.LastSeen = time.Now()
	pc.uidCache[uid] = info
}

// GetPodInfoByUID retrieves pod info for a pod UID
func (pc *PodCache) GetPodInfoByUID(uid string) PodInfo {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	if info, ok := pc.uidCache[uid]; ok {
		return info
	}
	return PodInfo{}
}

// Cleanup removes stale entries from the cache
func (pc *PodCache) Cleanup() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, info := range pc.cache {
		if info.LastSeen.Before(cutoff) {
			delete(pc.cache, ip)
		}
	}
}

// Helper functions

func isZtunnelPort(port uint16) bool {
	return port == ZtunnelInboundPort ||
		port == ZtunnelOutboundPort ||
		port == ZtunnelInboundPlain
}

// isExternalIP returns true for IPs outside cluster CIDRs (pod, service, docker-compose)
func isExternalIP(ip string) bool {
	if ip == "" || ip == "0.0.0.0" {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return false
	}
	b := parsed.To4()
	// Pod CIDR 10.42.0.0/16, Service 10.43.0.0/16, Docker 172.21.0.0/16
	if b[0] == 10 && (b[1] == 42 || b[1] == 43) {
		return false
	}
	if b[0] == 172 && b[1] == 21 {
		return false
	}
	return true
}

// GetOrLookup returns cached hostname for IP, or triggers async reverse lookup
func (d *DNSCache) GetOrLookup(ip string) string {
	d.mu.RLock()
	if h, ok := d.cache[ip]; ok {
		d.mu.RUnlock()
		return h
	}
	d.mu.RUnlock()
	// Async reverse lookup (don't block the hot path)
	go func() {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			hostname := strings.TrimSuffix(names[0], ".")
			d.mu.Lock()
			d.cache[ip] = hostname
			d.mu.Unlock()
		}
	}()
	return ""
}

func extractDstPort(event SecurityEvent) uint16 {
	// Network data structure: family(4) + type(4) + protocol(4) + src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2)
	// dst_port is at offset 46 (12 + 16 + 16 + 2)
	// Stored in host byte order (little-endian) by the eBPF program after bpf_ntohs.
	const offset = 46
	if len(event.Data.Raw) > offset+1 {
		return binary.LittleEndian.Uint16(event.Data.Raw[offset : offset+2])
	}
	return 0
}

func extractProtocol(event SecurityEvent) string {
	// protocol is at offset 8, 4 bytes. IPPROTO_TCP=6, IPPROTO_UDP=17
	const offset = 8
	if len(event.Data.Raw) > offset+3 {
		proto := binary.LittleEndian.Uint32(event.Data.Raw[offset : offset+4])
		if proto == 17 {
			return "UDP"
		}
	}
	return "TCP"
}

func extractSrcPort(event SecurityEvent) uint16 {
	// src_port is at offset 44 (12 + 16 + 16)
	// Stored in host byte order (little-endian) by the eBPF program (skc_num is already host order).
	const offset = 44
	if len(event.Data.Raw) > offset+1 {
		return binary.LittleEndian.Uint16(event.Data.Raw[offset : offset+2])
	}
	return 0
}

func extractBytesSent(event SecurityEvent) int64 {
	// bytes_sent is at offset 52 in the network union:
	// family(4) + type(4) + protocol(4) + src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2) + direction(1) + pad(3) = 52
	const offset = 52
	if len(event.Data.Raw) > offset+7 {
		return int64(binary.LittleEndian.Uint64(event.Data.Raw[offset : offset+8]))
	}
	return 0
}

func extractBytesReceived(event SecurityEvent) int64 {
	// bytes_received is at offset 60 in the network union:
	// bytes_sent offset (52) + 8 = 60
	const offset = 60
	if len(event.Data.Raw) > offset+7 {
		return int64(binary.LittleEndian.Uint64(event.Data.Raw[offset : offset+8]))
	}
	return 0
}

func extractIPv4(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	return net.IPv4(data[0], data[1], data[2], data[3]).String()
}

// extractIPv4FromLittleEndian extracts an IPv4 address from a little-endian uint32 stored in bytes
func extractIPv4FromLittleEndian(data []byte) string {
	if len(data) < 4 {
		return ""
	}
	addr := binary.LittleEndian.Uint32(data)
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	).String()
}

// logConvertDebug2 logs diagnostic info for mesh events including pod resolution (temporary debug).
// Uses a periodic counter that resets every 30s to allow continuous visibility.
var meshDebugCount int32
var meshDebugResetTime int64 // unix timestamp of last reset

func (mf *MeshForwarder) logConvertDebug2(srcIP, dstIP string, dstPort, srcPort uint16, event SecurityEvent, srcPod, dstPod PodInfo) {
	// Reset counter every 30 seconds
	now := time.Now().Unix()
	lastReset := atomic.LoadInt64(&meshDebugResetTime)
	if now-lastReset >= 30 {
		if atomic.CompareAndSwapInt64(&meshDebugResetTime, lastReset, now) {
			atomic.StoreInt32(&meshDebugCount, 0)
		}
	}

	n := atomic.AddInt32(&meshDebugCount, 1)
	if n <= 10 {
		comm := extractComm(event.Comm[:])
		mf.logger.Printf("mesh-debug: #%d comm=%s pid=%d srcIP=%s dstIP=%s dstPort=%d src=%s/%s dst=%s/%s",
			n, comm, event.PID, srcIP, dstIP, dstPort,
			srcPod.Namespace, srcPod.Name, dstPod.Namespace, dstPod.Name)
	}
}

func extractComm(comm []byte) string {
	// Find null terminator
	for i, b := range comm {
		if b == 0 {
			return string(comm[:i])
		}
	}
	return string(comm)
}

func buildSPIFFE(orgID uint, clusterID string, pod PodInfo) string {
	if pod.Namespace == "" || pod.ServiceAccount == "" {
		return ""
	}
	return fmt.Sprintf("spiffe://prysm.io/org/%d/cluster/%s/ns/%s/sa/%s",
		orgID, clusterID, pod.Namespace, pod.ServiceAccount)
}

// getPodInfoByPID finds pod info for a process by reading its cgroup and matching pod UID.
// Falls back to the proactively-built PID cache for short-lived processes that may have
// already exited by the time we process the eBPF event.
func (mf *MeshForwarder) getPodInfoByPID(pid uint32) PodInfo {
	// First try the proactive PID cache (works even if PID is already dead)
	mf.podCache.pidMu.RLock()
	if info, ok := mf.podCache.pidCache[pid]; ok {
		mf.podCache.pidMu.RUnlock()
		return info
	}
	mf.podCache.pidMu.RUnlock()

	// Try reading proc/<pid>/cgroup directly (works for long-lived processes)
	cgroupPath := filepath.Join(mf.procRoot, fmt.Sprintf("%d", pid), "cgroup")
	data, err := os.ReadFile(cgroupPath)
	if err != nil {
		return PodInfo{}
	}

	cgroupStr := string(data)
	podUID := extractPodUIDFromCgroup(cgroupStr)
	if podUID == "" {
		return PodInfo{}
	}

	info := mf.podCache.GetPodInfoByUID(podUID)
	// Cache for future lookups
	if info.Name != "" {
		mf.podCache.pidMu.Lock()
		mf.podCache.pidCache[pid] = info
		mf.podCache.pidMu.Unlock()
	}
	return info
}

// refreshPIDCache scans proc to build a PID → pod mapping.
// This is critical for resolving short-lived processes (curl, wget, nc) that exit
// before the eBPF event is processed in userspace.
func (mf *MeshForwarder) refreshPIDCache() int {
	entries, err := os.ReadDir(mf.procRoot)
	if err != nil {
		return 0
	}

	newCache := make(map[uint32]PodInfo)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '1' || name[0] > '9' {
			continue
		}

		// Parse PID
		var pid uint32
		for _, ch := range name {
			if ch < '0' || ch > '9' {
				pid = 0
				break
			}
			pid = pid*10 + uint32(ch-'0')
		}
		if pid == 0 {
			continue
		}

		cgroupPath := filepath.Join(mf.procRoot, name, "cgroup")
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}

		cgroupStr := string(data)
		if !strings.Contains(cgroupStr, "kubepods") {
			continue
		}

		podUID := extractPodUIDFromCgroup(cgroupStr)
		if podUID == "" {
			continue
		}

		info := mf.podCache.GetPodInfoByUID(podUID)
		if info.Name != "" {
			newCache[pid] = info
		}
	}

	mf.podCache.pidMu.Lock()
	mf.podCache.pidCache = newCache
	mf.podCache.pidMu.Unlock()
	return len(newCache)
}

// extractPodUIDFromCgroup extracts the pod UID from a cgroup path string
func extractPodUIDFromCgroup(cgroupStr string) string {
	// Common patterns:
	// 1. /kubepods/burstable/pod<uid>/...
	// 2. /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/...
	// 3. /kubepods/pod<uid>/...

	lines := strings.Split(cgroupStr, "\n")
	for _, line := range lines {
		// Look for "pod" followed by a UUID
		if idx := strings.Index(line, "pod"); idx != -1 {
			// Extract potential UID after "pod"
			rest := line[idx+3:] // skip "pod"

			// Find the end of the UID (common delimiters: /, ., -, \n)
			var uid strings.Builder
			for _, ch := range rest {
				if ch == '/' || ch == '.' || ch == '\n' {
					break
				}
				if ch == '_' {
					uid.WriteRune('-') // Convert underscores to dashes
				} else {
					uid.WriteRune(ch)
				}
			}

			result := uid.String()
			// Validate it looks like a UUID (has dashes or is 32+ chars)
			if len(result) >= 32 || strings.Count(result, "-") >= 3 {
				return result
			}
		}
	}
	return ""
}
