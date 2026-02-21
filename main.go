package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"ebpf-collector/output"
	"ebpf-collector/rules"
)

// Config captures runtime configuration derived from environment variables.
type Config struct {
	OrgID             uint
	SinkID            uint
	Endpoint          string
	Token             string
	NodeName          string
	ClusterID         string
	Namespace         string
	HeartbeatInterval time.Duration
	HTTPTimeout       time.Duration
	MeshEnabled       bool   // Enable ztunnel/service mesh event forwarding
	MeshEndpoint      string // Optional: backend URL for mesh events (POST /api/v1/agent/ztunnel/events). If empty, derived from Endpoint.
	MeshCaptureAll    bool   // Capture all TCP connections for mesh topology, not just ztunnel ports
	ProcRoot          string // Root path for /proc (use /host/proc when host proc is mounted there in containers)
}

// Collector is a hardened security monitoring daemon that uses eBPF programs
// to collect kernel-level security events and forwards them to the Prysm
// log ingestion endpoint.
type Collector struct {
	cfg              Config
	httpClient       *http.Client
	logger           *log.Logger
	ebpfManager      *EBPFManager
	securityManager  *SecurityManager
	signatureManager *SignatureManager
	eventProcessor   *SecureEventProcessor
	malwareDetector  *MalwareDetector
	meshForwarder    *MeshForwarder
	processTree      *ProcessTree
	containerEnricher *ContainerEnricher
	eventEnricher    *EventEnricher
	userResolver     *UserResolver
	rulesEngine      *rules.Engine
	outputWriter     output.Writer
	tlsCapture       *TLSCapture // nil when PRYSM_TLS_CAPTURE != "true"
	batchSender      *BatchSender
	// Rate-limit per-event error logs to avoid log spam when many events fail
	eventErrorMu   sync.Mutex
	lastEventError map[string]time.Time
}

// BatchSender accumulates log entries and sends them in batches to reduce
// HTTP request overhead. Entries are flushed when the buffer reaches
// maxEntries or every flushInterval, whichever comes first.
type BatchSender struct {
	mu            sync.Mutex
	entries       []logEntry
	maxEntries    int
	flushInterval time.Duration
	sendFn        func(ingestionRequest) error
	cfg           Config
	logger        *log.Logger
	stopCh        chan struct{}
	doneCh        chan struct{}
}

// NewBatchSender creates a BatchSender that flushes buffered entries
// either when maxEntries is reached or every flushInterval.
func NewBatchSender(cfg Config, logger *log.Logger, maxEntries int, flushInterval time.Duration, sendFn func(ingestionRequest) error) *BatchSender {
	return &BatchSender{
		entries:       make([]logEntry, 0, maxEntries),
		maxEntries:    maxEntries,
		flushInterval: flushInterval,
		sendFn:        sendFn,
		cfg:           cfg,
		logger:        logger,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
}

// Start begins the periodic flush goroutine.
func (bs *BatchSender) Start() {
	go func() {
		defer close(bs.doneCh)
		ticker := time.NewTicker(bs.flushInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				bs.Flush()
			case <-bs.stopCh:
				bs.Flush() // drain remaining entries on shutdown
				return
			}
		}
	}()
}

// Stop signals the flush goroutine to drain and exit.
func (bs *BatchSender) Stop() {
	close(bs.stopCh)
	<-bs.doneCh
}

// Enqueue adds an entry to the buffer and flushes if full.
func (bs *BatchSender) Enqueue(entry logEntry) {
	bs.mu.Lock()
	bs.entries = append(bs.entries, entry)
	if len(bs.entries) >= bs.maxEntries {
		entries := bs.entries
		bs.entries = make([]logEntry, 0, bs.maxEntries)
		bs.mu.Unlock()
		bs.send(entries)
		return
	}
	bs.mu.Unlock()
}

// Flush sends all buffered entries immediately.
func (bs *BatchSender) Flush() {
	bs.mu.Lock()
	if len(bs.entries) == 0 {
		bs.mu.Unlock()
		return
	}
	entries := bs.entries
	bs.entries = make([]logEntry, 0, bs.maxEntries)
	bs.mu.Unlock()
	bs.send(entries)
}

func (bs *BatchSender) send(entries []logEntry) {
	payload := ingestionRequest{
		AgentToken: bs.cfg.Token,
		BatchID:    uuid.New().String(),
		ClusterID:  bs.cfg.ClusterID,
		Timestamp:  time.Now().UTC(),
		Logs:       entries,
	}
	if err := bs.sendFn(payload); err != nil {
		bs.logger.Printf("failed to send batch (%d entries): %v", len(entries), err)
	}
}

func main() {
	versionFlag := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println("prysm-ebpf-collector dev")
		return
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	rand.Seed(time.Now().UnixNano())

	logger := log.New(os.Stdout, "[ebpf-collector] ", log.LstdFlags|log.Lmsgprefix)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	collector := NewCollector(cfg, logger)
	if err := collector.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Fatalf("collector stopped with error: %v", err)
	}
}

// NewCollector constructs a Collector and initialises shared resources.
func NewCollector(cfg Config, logger *log.Logger) *Collector {
	// Verify security capabilities first
	if err := VerifyCapabilities(); err != nil {
		logger.Fatalf("insufficient capabilities: %v", err)
	}

	client := &http.Client{
		Timeout: cfg.HTTPTimeout,
	}

	// Initialize security components
	securityManager, err := NewSecurityManager()
	if err != nil {
		logger.Fatalf("failed to initialize security manager: %v", err)
	}

	signatureManager, err := NewSignatureManager()
	if err != nil {
		logger.Fatalf("failed to initialize signature manager: %v", err)
	}

	// Initialize secure event processor
	eventProcessor, err := NewSecureEventProcessor("ebpf-encryption-key-" + cfg.ClusterID)
	if err != nil {
		logger.Fatalf("failed to initialize event processor: %v", err)
	}

	ebpfDir := os.Getenv("PRYSM_EBPF_ASSET_DIR")
	if ebpfDir == "" {
		ebpfDir = "./ebpf"
	}

	ebpfManager, err := NewEBPFManager(ebpfDir)
	if err != nil {
		logger.Fatalf("failed to initialize eBPF manager: %v", err)
	}

	// Initialize process tree (bootstraps from /proc)
	processTree := NewProcessTree()

	// Initialize container enricher
	containerEnricher := NewContainerEnricher(cfg.ProcRoot, logger)

	// Initialize event enricher
	eventEnricher := NewEventEnricher(processTree, containerEnricher)

	// Initialize user resolver for UID→username mapping
	userResolver := NewUserResolver(cfg.ProcRoot)

	// Initialize malware detector with callback for detected threats
	var malwareDetector *MalwareDetector

	// Initialize rules engine with CEL-based YAML rules.
	builtinRulesDir := filepath.Join(ebpfDir, "..", "rules", "builtin")
	customRulesDir := strings.TrimSpace(os.Getenv("PRYSM_RULES_DIR"))

	var rulesEngine *rules.Engine
	// The rules engine is created here but its onAlert callback requires the
	// collector, so we set it after construction via a closure below.
	// We pass nil onAlert during construction and wire it later.
	rulesEngine, err = rules.NewEngine(builtinRulesDir, customRulesDir, logger, nil)
	if err != nil {
		logger.Printf("warning: rules engine init failed (detections will use legacy engine): %v", err)
		rulesEngine = nil
	} else {
		logger.Printf("rules engine initialized with %d rules", rulesEngine.RuleCount())
	}

	// Initialize output writers for alerts (stdout, file, syslog).
	var outputWriters []output.Writer
	if alertFile := strings.TrimSpace(os.Getenv("PRYSM_ALERT_FILE")); alertFile != "" {
		fw, ferr := output.NewFileWriter(alertFile, 50*1024*1024, 5) // 50MB, 5 rotations
		if ferr != nil {
			logger.Printf("warning: failed to open alert file %s: %v", alertFile, ferr)
		} else {
			outputWriters = append(outputWriters, fw)
			logger.Printf("alert file output enabled: %s", alertFile)
		}
	}
	if strings.ToLower(strings.TrimSpace(os.Getenv("PRYSM_ALERT_STDOUT"))) == "true" {
		outputWriters = append(outputWriters, output.NewStdoutWriter())
		logger.Println("alert stdout output enabled")
	}
	var outputWriter output.Writer
	if len(outputWriters) > 0 {
		outputWriter = output.NewMultiWriter(logger, outputWriters...)
	}

	// Initialize mesh forwarder for ztunnel/service mesh events
	meshForwarder := NewMeshForwarder(cfg, logger)

	// Register mesh callback on eBPF manager so network events are routed
	// directly from the ring buffer reader to the mesh forwarder, bypassing
	// the shared eventChan that gets saturated by syscall/process events.
	ebpfManager.SetMeshEventCallback(func(event SecurityEvent) bool {
		if meshForwarder != nil {
			return meshForwarder.ProcessSecurityEvent(event)
		}
		return false
	})

	c := &Collector{
		cfg:               cfg,
		httpClient:        client,
		logger:            logger,
		ebpfManager:       ebpfManager,
		securityManager:   securityManager,
		signatureManager:  signatureManager,
		eventProcessor:    eventProcessor,
		malwareDetector:   malwareDetector,
		meshForwarder:     meshForwarder,
		processTree:       processTree,
		containerEnricher: containerEnricher,
		eventEnricher:     eventEnricher,
		userResolver:      userResolver,
		rulesEngine:       rulesEngine,
		outputWriter:      outputWriter,
		lastEventError:    make(map[string]time.Time),
	}

	// Initialize batch sender: flush every 2s or when 500 entries accumulate.
	c.batchSender = NewBatchSender(cfg, logger, 500, 2*time.Second, c.sendBatch)
	logger.Println("batch sender initialized (max=500 entries, interval=2s)")

	// Wire up rules engine onAlert callback now that the collector exists.
	if rulesEngine != nil {
		rulesEngine, err = rules.NewEngine(builtinRulesDir, customRulesDir, logger, func(alert rules.Alert) {
			c.handleRuleAlert(alert)
		})
		if err != nil {
			logger.Printf("warning: rules engine re-init failed: %v", err)
		} else {
			c.rulesEngine = rulesEngine
		}
	}

	// Initialize TLS plaintext interception (opt-in via PRYSM_TLS_CAPTURE=true).
	if strings.ToLower(strings.TrimSpace(os.Getenv("PRYSM_TLS_CAPTURE"))) == "true" {
		tlsCapture := NewTLSCapture(cfg, logger, processTree, containerEnricher, c.rulesEngine, c.outputWriter, func(det ThreatDetection) {
			c.handleThreatDetection(det)
		})
		if tlsCapture != nil {
			c.tlsCapture = tlsCapture
			logger.Println("TLS plaintext interception enabled")
		} else {
			logger.Println("TLS plaintext interception requested but initialization failed")
		}
	}

	return c
}

// Run blocks until the context is cancelled. It starts eBPF monitoring
// and processes security events, forwarding them to the Prysm ingestion service.
func (c *Collector) Run(ctx context.Context) error {
	c.logger.Printf("starting eBPF security collector for org=%d sink=%d node=%q cluster=%q endpoint=%q",
		c.cfg.OrgID, c.cfg.SinkID, c.cfg.NodeName, c.cfg.ClusterID, c.cfg.Endpoint)

	// Initialize malware detector with threat detection callback
	c.malwareDetector = NewMalwareDetector(func(detection ThreatDetection) {
		c.handleThreatDetection(detection)
	})
	c.logger.Println("malware detection engine initialized")

	if err := c.inspectKernelEnvironment(); err != nil {
		c.logger.Printf("warning: kernel environment inspection failed: %v", err)
	}

	// Initialize eBPF programs
	if err := c.initializeEBPF(); err != nil {
		return fmt.Errorf("eBPF initialization failed: %w", err)
	}

	// Start batch sender for buffered log delivery
	c.batchSender.Start()

	// Start event processing goroutine
	go c.processEvents(ctx)

	// Start mesh forwarder for ztunnel/service mesh events
	c.meshForwarder.Start(ctx)

	// Start TLS plaintext interception if enabled
	if c.tlsCapture != nil {
		go c.tlsCapture.Start(ctx)
	}

	ticker := time.NewTicker(c.cfg.HeartbeatInterval)
	defer ticker.Stop()

	// Immediately attempt a heartbeat so the backend sees activity soon after startup.
	c.emitHeartbeat()

	for {
		select {
		case <-ctx.Done():
			c.logger.Println("shutdown signal received, stopping collector")
			c.batchSender.Stop() // drain buffered entries before exit
			if c.tlsCapture != nil {
				c.tlsCapture.Close()
			}
			c.ebpfManager.Stop()
			return ctx.Err()
		case <-ticker.C:
			c.emitHeartbeat()
		}
	}
}

// emitHeartbeat constructs and transmits a status heartbeat to indicate
// the eBPF collector is running and operational.
func (c *Collector) emitHeartbeat() {
	if c.cfg.Endpoint == "" || c.cfg.Token == "" {
		c.logger.Println("heartbeat skipped: missing endpoint or token")
		return
	}
	if c.cfg.ClusterID == "" {
		c.logger.Println("heartbeat skipped: cluster ID not configured")
		return
	}

	batchID := uuid.New().String()
	now := time.Now().UTC()

	entry := logEntry{
		Timestamp: now,
		Level:     "info",
		Message:   fmt.Sprintf("eBPF security collector active on node %s", c.cfg.NodeName),
		Source:    "security",
		ClusterID: c.cfg.ClusterID,
		Node:      c.cfg.NodeName,
		Namespace: c.cfg.Namespace,
		Metadata: map[string]any{
			"org_id":           c.cfg.OrgID,
			"sink_id":          c.cfg.SinkID,
			"signals":          []string{"network", "process", "syscall", "file", "container"},
			"rand":             rand.Int63(),
			"kernel_bpf":       filepath.Join("/sys/fs/bpf"),
			"mode":             "ebpf",
			"ebpf_stats":       c.getEBPFStats(),
			"security_info":    c.getSecurityInfo(),
			"encryption_stats": c.eventProcessor.GetEncryptionStats(),
			"tls_capture":      c.getTLSCaptureStats(),
		},
		Tags: []string{"ebpf", "security", "heartbeat"},
	}

	payload := ingestionRequest{
		AgentToken: c.cfg.Token,
		BatchID:    batchID,
		ClusterID:  c.cfg.ClusterID,
		Timestamp:  now,
		Logs:       []logEntry{entry},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		c.logger.Printf("failed to marshal heartbeat payload: %v", err)
		return
	}

	req, err := http.NewRequest("POST", c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		c.logger.Printf("failed to build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("User-Agent", "prysm-ebpf-collector/0.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Printf("heartbeat delivery failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		c.logger.Printf("heartbeat rejected: status=%d", resp.StatusCode)
		return
	}

	c.logger.Printf("heartbeat batch=%s delivered successfully", batchID)
}

// inspectKernelEnvironment logs information about the host-mounted paths that
// the eBPF programs require for operation.
func (c *Collector) inspectKernelEnvironment() error {
	paths := []string{"/sys/fs/bpf", "/lib/modules", "/usr/src"}
	missing := make([]string, 0, len(paths))

	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				missing = append(missing, p)
				continue
			}
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	if len(missing) > 0 {
		c.logger.Printf("warning: expected host paths not available: %s", strings.Join(missing, ", "))
		c.logger.Println("eBPF programs may not function properly without proper host mounts")
	} else {
		c.logger.Println("kernel environment ready for eBPF (bpf, modules, sources mounted)")
	}
	return nil
}

// parseOrgIDFromToken extracts organization ID from agent token
// Token format: tkn_<base64(org_{orgID}_{randomHex})>
func parseOrgIDFromToken(token string) (uint, error) {
	const prefix = "tkn_"
	if !strings.HasPrefix(token, prefix) {
		return 0, fmt.Errorf("invalid token format: missing tkn_ prefix")
	}

	// Remove prefix and decode base64
	encoded := token[len(prefix):]

	// Add padding if needed
	if pad := len(encoded) % 4; pad != 0 {
		encoded += strings.Repeat("=", 4-pad)
	}

	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, fmt.Errorf("invalid token format: base64 decode failed: %w", err)
	}

	// Parse org_<ID>_ from decoded string
	var orgID uint
	if _, err := fmt.Sscanf(string(decoded), "org_%d_", &orgID); err != nil {
		return 0, fmt.Errorf("invalid token format: org ID parse failed: %w", err)
	}

	return orgID, nil
}

// loadConfig parses configuration from environment variables.
func loadConfig() (Config, error) {
	getUintOptional := func(key string, fallback uint) uint {
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			return fallback
		}
		num, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return fallback
		}
		return uint(num)
	}

	endpoint := strings.TrimSpace(os.Getenv("PRYSM_EBPF_ENDPOINT"))
	token := strings.TrimSpace(os.Getenv("PRYSM_LOG_TOKEN"))
	nodeName := fallbackEnv("NODE_NAME", fallbackEnv("HOSTNAME", "unknown-node"))
	clusterID := strings.TrimSpace(os.Getenv("PRYSM_CLUSTER_ID"))
	namespace := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))

	// Try to extract org ID from token first, fall back to env var
	var orgID uint
	if token != "" {
		if parsedOrgID, err := parseOrgIDFromToken(token); err == nil {
			orgID = parsedOrgID
		}
	}

	// Override with explicit env var if set
	if envOrgID := strings.TrimSpace(os.Getenv("PRYSM_ORG_ID")); envOrgID != "" {
		if parsed, err := strconv.ParseUint(envOrgID, 10, 64); err == nil {
			orgID = uint(parsed)
		}
	}

	if orgID == 0 {
		return Config{}, fmt.Errorf("PRYSM_ORG_ID is required (or provide valid PRYSM_LOG_TOKEN)")
	}

	// Sink ID defaults to 1 if not specified
	sinkID := getUintOptional("PRYSM_SINK_ID", 1)

	heartbeatInterval := parseDurationEnv("HEARTBEAT_INTERVAL", 5*time.Minute)
	httpTimeout := parseDurationEnv("HTTP_TIMEOUT", 10*time.Second)

	// Mesh forwarding is enabled by default, can be disabled with MESH_ENABLED=false
	meshEnabled := true
	if meshEnv := strings.ToLower(strings.TrimSpace(os.Getenv("MESH_ENABLED"))); meshEnv == "false" || meshEnv == "0" {
		meshEnabled = false
	}

	// PRYSM_MESH_ENDPOINT: backend URL for mesh/ztunnel events. Must point to backend (not ingestion API).
	// Example: http://backend:8080/api/v1/agent/ztunnel/events
	meshEndpoint := strings.TrimSuffix(strings.TrimSpace(os.Getenv("PRYSM_MESH_ENDPOINT")), "/")

	// MESH_CAPTURE_ALL: capture all TCP connections for mesh topology, not just ztunnel ports
	meshCaptureAll := false
	if captureAllEnv := strings.ToLower(strings.TrimSpace(os.Getenv("MESH_CAPTURE_ALL"))); captureAllEnv == "true" || captureAllEnv == "1" {
		meshCaptureAll = true
	}

	// HOST_PROC: when host /proc is mounted at /host/proc (e.g. in K8s), use this for PID→pod resolution
	procRoot := strings.TrimSuffix(strings.TrimSpace(os.Getenv("HOST_PROC")), "/")
	if procRoot == "" {
		procRoot = "/proc"
	}

	return Config{
		OrgID:             orgID,
		SinkID:            sinkID,
		Endpoint:          endpoint,
		Token:             token,
		NodeName:          nodeName,
		ClusterID:         clusterID,
		Namespace:         namespace,
		HeartbeatInterval: heartbeatInterval,
		HTTPTimeout:       httpTimeout,
		MeshEnabled:       meshEnabled,
		MeshEndpoint:      meshEndpoint,
		MeshCaptureAll:    meshCaptureAll,
		ProcRoot:          procRoot,
	}, nil
}

func parseDurationEnv(key string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return def
	}
	return d
}

func fallbackEnv(primary, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(primary)); val != "" {
		return val
	}
	return strings.TrimSpace(os.Getenv(fallback))
}

// ingestionRequest mirrors the payload expected by the log-ingestion service.
type ingestionRequest struct {
	AgentToken string     `json:"agent_token"`
	BatchID    string     `json:"batch_id"`
	ClusterID  string     `json:"cluster_id"`
	Timestamp  time.Time  `json:"timestamp"`
	Logs       []logEntry `json:"logs"`
}

type logEntry struct {
	Timestamp time.Time      `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Source    string         `json:"source"`
	ClusterID string         `json:"cluster_id"`
	Namespace string         `json:"namespace,omitempty"`
	Pod       string         `json:"pod,omitempty"`
	Container string         `json:"container,omitempty"`
	Node      string         `json:"node,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	Tags      []string       `json:"tags,omitempty"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// initializeEBPF loads and starts all eBPF programs with security verification
func (c *Collector) initializeEBPF() error {
	c.logger.Println("initializing eBPF programs with security verification...")

	// Verify eBPF program signatures
	ebpfDir := os.Getenv("PRYSM_EBPF_ASSET_DIR")
	if ebpfDir == "" {
		ebpfDir = "./ebpf"
	}

	if err := c.signatureManager.VerifyProgramSignatures(ebpfDir); err != nil {
		return fmt.Errorf("eBPF program signature verification failed: %w", err)
	}

	// Load eBPF programs
	if err := c.ebpfManager.LoadPrograms(ebpfDir); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Initialize suspicious lists for threat detection
	if err := c.ebpfManager.InitializeSuspiciousLists(); err != nil {
		c.logger.Printf("warning: failed to initialize suspicious lists: %v", err)
	}

	c.logger.Println("eBPF programs loaded and verified successfully")

	// Populate syscall filter with security-relevant syscalls.
	if err := c.ebpfManager.PopulateSyscallFilter(DefaultSecuritySyscalls()); err != nil {
		c.logger.Printf("warning: failed to populate syscall filter: %v", err)
	}

	return nil
}

// processEvents handles security events from eBPF programs
func (c *Collector) processEvents(ctx context.Context) {
	c.logger.Println("starting security event processing...")
	eventChan := c.ebpfManager.GetEventChannel()

	for {
		select {
		case <-ctx.Done():
			c.logger.Println("stopping event processing")
			return
		case event, ok := <-eventChan:
			if !ok {
				c.logger.Println("event channel closed")
				return
			}
			c.handleSecurityEvent(event)
		}
	}
}

// logEventErrorRateLimited logs an error at most once per key per 30s to avoid log spam
func (c *Collector) logEventErrorRateLimited(key, format string, args ...interface{}) {
	const interval = 30 * time.Second
	c.eventErrorMu.Lock()
	last := c.lastEventError[key]
	now := time.Now()
	if now.Sub(last) < interval {
		c.eventErrorMu.Unlock()
		return
	}
	c.lastEventError[key] = now
	c.eventErrorMu.Unlock()
	c.logger.Printf(format, args...)
}

// handleSecurityEvent securely processes a single security event and forwards it
func (c *Collector) handleSecurityEvent(event SecurityEvent) {
	if c.cfg.Endpoint == "" || c.cfg.Token == "" || c.cfg.ClusterID == "" {
		return // Skip if not properly configured
	}

	// Skip events with unknown/zero event type (malformed ring buffer records)
	if event.EventType < EventProcessExec || event.EventType > EventCredChange {
		return
	}

	// Feed process tree for lineage tracking
	comm := nullTerminatedString(event.Comm[:])
	containerID := nullTerminatedString(event.ContainerID[:])
	switch event.EventType {
	case EventProcessExec:
		filename := nullTerminatedString(event.Data.Raw[:256])
		argv := nullTerminatedString(event.Data.Raw[256:768])
		cmdline := argv
		if cmdline == "" {
			cmdline = filename
		}
		c.processTree.HandleExec(event.PID, event.PPID, event.UID, event.GID, comm, cmdline, containerID)
	case EventProcessExit:
		c.processTree.HandleExit(event.PID)
	}
	_ = comm
	_ = containerID

	// Skip kernel-internal events with PID 0 or empty comm — these are noise
	// from kernel threads and don't represent actionable security events
	if event.PID == 0 || nullTerminatedString(event.Comm[:]) == "" {
		return
	}

	// Check if this is a mesh/ztunnel event and forward it
	// Mesh events are processed separately and don't need to go through normal log ingestion
	if c.meshForwarder != nil && c.meshForwarder.ProcessSecurityEvent(event) {
		// Event was handled by mesh forwarder, skip normal processing to reduce noise
		// Mesh traffic is high-volume, we only want it in the mesh topology view
		return
	}

	// Validate and sanitize the event
	if err := c.securityManager.ValidateAndSanitizeEvent(&event); err != nil {
		c.logEventErrorRateLimited("validation", "event validation failed: %v", err)
		return
	}

	// Convert eBPF event to log entry BEFORE ProcessSecureEvent, which zeroes
	// the event struct via ClearMemory for security hardening.
	entry := c.convertEventToLogEntry(event)

	// Run rules engine on enriched event (CEL-based YAML rules)
	if c.rulesEngine != nil && c.eventEnricher != nil {
		enriched := c.eventEnricher.Enrich(event)
		c.evaluateRules(enriched)
	}

	// Run malware analysis on the event (reads fields before they are cleared)
	c.analyzeEventForMalware(&event)

	// Process through secure event processor (encrypts then clears the event)
	if err := c.eventProcessor.ProcessSecureEvent(&event); err != nil {
		c.logEventErrorRateLimited("processing", "secure event processing failed: %v", err)
		return
	}

	// Enqueue into batch sender instead of sending individually
	c.batchSender.Enqueue(entry)
}

// analyzeEventForMalware runs the event through the malware detection engine
func (c *Collector) analyzeEventForMalware(event *SecurityEvent) {
	if c.malwareDetector == nil {
		return
	}

	var detections []ThreatDetection

	switch event.EventType {
	case EventProcessExec:
		// Extract filename and argv from event data
		filename := nullTerminatedString(event.Data.Raw[:256])
		argv := nullTerminatedString(event.Data.Raw[256:768])
		detections = c.malwareDetector.AnalyzeProcessEvent(event, filename, argv)

	case EventNetworkConnect:
		// Extract network data: family(4) + type(4) + protocol(4) + src_addr(16) + dst_addr(16) + ports(4)
		data := event.Data.Raw[:]
		srcAddr := binary.LittleEndian.Uint32(data[12:16])
		dstAddr := binary.LittleEndian.Uint32(data[28:32])
		srcPort := binary.LittleEndian.Uint16(data[44:46])
		dstPort := binary.LittleEndian.Uint16(data[46:48])

		srcIP := uint32ToIPv4(srcAddr)
		dstIP := uint32ToIPv4(dstAddr)

		protocol := "tcp"
		if binary.LittleEndian.Uint32(data[8:12]) == 17 {
			protocol = "udp"
		}

		detections = c.malwareDetector.AnalyzeNetworkEvent(event, srcIP, dstIP, srcPort, dstPort, protocol)

	case EventFileAccess:
		// Extract filename, flags, mode from event data
		filename := nullTerminatedString(event.Data.Raw[:256])
		flags := binary.LittleEndian.Uint32(event.Data.Raw[256:260])
		mode := binary.LittleEndian.Uint32(event.Data.Raw[260:264])
		detections = c.malwareDetector.AnalyzeFileEvent(event, filename, flags, mode)

	case EventSyscallAnomaly:
		// Extract syscall number and args
		data := event.Data.Raw[:]
		syscallNr := binary.LittleEndian.Uint64(data[0:8])
		var args [6]uint64
		for i := 0; i < 6; i++ {
			args[i] = binary.LittleEndian.Uint64(data[8+i*8 : 16+i*8])
		}
		detections = c.malwareDetector.AnalyzeSyscallEvent(event, syscallNr, args)
	}

	// Process any detected threats
	for _, detection := range detections {
		c.handleThreatDetection(detection)
	}
}

// handleThreatDetection processes a detected threat and sends an alert
func (c *Collector) handleThreatDetection(detection ThreatDetection) {
	// Log the detection
	c.logger.Printf("THREAT DETECTED [%s/%s] score=%d: %s",
		detection.Category, detection.Level, detection.Score, detection.Description)

	// Create a high-priority log entry for the threat
	entry := logEntry{
		Timestamp: detection.Timestamp,
		Level:     c.threatLevelToLogLevel(detection.Level),
		Message:   detection.Description,
		Source:    "security",
		ClusterID: c.cfg.ClusterID,
		Node:      c.cfg.NodeName,
		Namespace: c.cfg.Namespace,
		Tags:      []string{"ebpf", "security", "threat", string(detection.Category), detection.Level.String()},
		Metadata: map[string]any{
			"org_id":       c.cfg.OrgID,
			"sink_id":      c.cfg.SinkID,
			"threat_type":  string(detection.Category),
			"threat_level": detection.Level.String(),
			"threat_score": detection.Score,
			"indicators":   detection.Indicators,
			"mitre_attck":  detection.MitreATTCK,
		},
	}

	// Add process info if available
	if detection.ProcessInfo != nil {
		entry.Metadata["process"] = map[string]any{
			"pid":          detection.ProcessInfo.PID,
			"ppid":         detection.ProcessInfo.PPID,
			"uid":          detection.ProcessInfo.UID,
			"comm":         detection.ProcessInfo.Comm,
			"cmdline":      detection.ProcessInfo.Cmdline,
			"ancestors":    detection.ProcessInfo.Ancestors,
			"container_id": detection.ProcessInfo.ContainerID,
		}
		if detection.ProcessInfo.ContainerID != "" {
			entry.Container = detection.ProcessInfo.ContainerID
		}
	}

	// Add network info if available
	if detection.NetworkInfo != nil {
		entry.Metadata["network"] = map[string]any{
			"src_ip":   detection.NetworkInfo.SrcIP,
			"dst_ip":   detection.NetworkInfo.DstIP,
			"src_port": detection.NetworkInfo.SrcPort,
			"dst_port": detection.NetworkInfo.DstPort,
			"protocol": detection.NetworkInfo.Protocol,
		}
	}

	// Add file info if available
	if detection.FileInfo != nil {
		entry.Metadata["file"] = map[string]any{
			"path":      detection.FileInfo.Path,
			"operation": detection.FileInfo.Operation,
			"mode":      detection.FileInfo.Mode,
		}
	}

	// Enqueue threat alert into batch sender
	c.batchSender.Enqueue(entry)
}

// threatLevelToLogLevel converts threat level to log level.
// All threat detections are security-significant — even ThreatLow is a "warn"
// because the malware detector only fires for genuinely suspicious behavior.
func (c *Collector) threatLevelToLogLevel(level ThreatLevel) string {
	switch level {
	case ThreatLow:
		return "warn"
	case ThreatMedium:
		return "warn"
	case ThreatHigh:
		return "error"
	case ThreatCritical:
		return "fatal"
	default:
		return "warn"
	}
}

// uint32ToIPv4 converts a uint32 to an IPv4 address
func uint32ToIPv4(addr uint32) net.IP {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	)
}

// convertEventToLogEntry converts an eBPF SecurityEvent to a log entry
func (c *Collector) convertEventToLogEntry(event SecurityEvent) logEntry {
	// Convert eBPF timestamp (nanoseconds since boot) to time.Time
	// Fall back to current time if timestamp is 0 or results in an invalid time
	timestamp := time.Unix(0, int64(event.Timestamp))
	if event.Timestamp == 0 || timestamp.Year() < 2020 {
		timestamp = time.Now().UTC()
	}

	// Extract comm and container ID as null-terminated strings
	comm := nullTerminatedString(event.Comm[:])
	containerID := nullTerminatedString(event.ContainerID[:])

	// Start with the kernel-reported level as a baseline
	level := c.getEventLevel(event.SecurityLevel)

	// Create base entry
	entry := logEntry{
		Timestamp: timestamp,
		Level:     level,
		Source:    "security",
		ClusterID: c.cfg.ClusterID,
		Node:      c.cfg.NodeName,
		Namespace: c.cfg.Namespace,
		Tags:      []string{"ebpf", "security", c.getEventTypeTag(event.EventType)},
		Metadata: map[string]any{
			"org_id":         c.cfg.OrgID,
			"sink_id":        c.cfg.SinkID,
			"event_type":     event.EventType,
			"security_level": event.SecurityLevel,
			"pid":            event.PID,
			"tgid":           event.TGID,
			"uid":            event.UID,
			"gid":            event.GID,
			"comm":           comm,
		},
	}

	if containerID != "" {
		entry.Container = containerID
		entry.Metadata["container_id"] = containerID
	}

	// Set message, tags, and apply userspace severity classification based
	// on what the event actually represents. The kernel sets SecurityLevel=0
	// (info) for most events, so we override here with meaningful levels.
	switch event.EventType {
	case EventProcessExec:
		filename := nullTerminatedString(event.Data.Raw[:256])
		entry.Message = fmt.Sprintf("Process execution: %s (PID %d)", comm, event.PID)
		entry.Tags = append(entry.Tags, "process", "exec")
		entry.Metadata["exec_path"] = filename
		// Process exec in a container is always at least a warning
		if containerID != "" {
			entry.Level = elevate(entry.Level, "warn")
		}
		// Root process execution is noteworthy
		if event.UID == 0 && containerID != "" {
			entry.Level = elevate(entry.Level, "warn")
			entry.Tags = append(entry.Tags, "root_exec")
		}

	case EventNetworkConnect:
		entry.Message = fmt.Sprintf("Network connection from %s (PID %d)", comm, event.PID)
		entry.Tags = append(entry.Tags, "network", "connection")
		// Network events are at least warn — they represent observable behavior
		entry.Level = elevate(entry.Level, "warn")

	case EventFileAccess:
		filename := nullTerminatedString(event.Data.Raw[:256])
		entry.Message = fmt.Sprintf("File access: %s by %s (PID %d)", filename, comm, event.PID)
		entry.Tags = append(entry.Tags, "file", "access")
		entry.Metadata["file_path"] = filename
		// Classify file access severity by path
		switch {
		case strings.HasPrefix(filename, "/var/run/secrets/") || strings.HasPrefix(filename, "/run/secrets/"):
			entry.Level = elevate(entry.Level, "error")
			entry.Tags = append(entry.Tags, "secret_access", "k8s_secret")
			entry.Message = fmt.Sprintf("K8s secret read: %s by %s (PID %d)", filename, comm, event.PID)
		case strings.Contains(filename, "/etc/shadow") || strings.Contains(filename, "/etc/gshadow"):
			entry.Level = elevate(entry.Level, "error")
			entry.Tags = append(entry.Tags, "credential_access")
		case strings.Contains(filename, ".ssh/") || strings.Contains(filename, ".aws/credentials") ||
			strings.Contains(filename, ".kube/config"):
			entry.Level = elevate(entry.Level, "error")
			entry.Tags = append(entry.Tags, "credential_access")
		case strings.Contains(filename, "/etc/sudoers") || strings.Contains(filename, "ld.so.preload"):
			entry.Level = elevate(entry.Level, "error")
			entry.Tags = append(entry.Tags, "system_tampering")
		default:
			entry.Level = elevate(entry.Level, "warn")
		}

	case EventSyscallAnomaly:
		sd := event.Data.ParseSyscallData()
		syscallName := SyscallName(sd.SyscallNr)
		entry.Message = fmt.Sprintf("Suspicious syscall: %s (%d) by %s (PID %d)", syscallName, sd.SyscallNr, comm, event.PID)
		entry.Tags = append(entry.Tags, "syscall", "anomaly", syscallName)
		entry.Metadata["syscall_nr"] = sd.SyscallNr
		entry.Metadata["syscall_name"] = syscallName
		// Syscall anomalies are security-relevant by definition — at least warn
		entry.Level = elevate(entry.Level, "warn")
		// Privilege/module syscalls are high severity
		switch sd.SyscallNr {
		case 101: // ptrace
			entry.Level = elevate(entry.Level, "error")
		case 175, 176: // init_module, delete_module
			entry.Level = elevate(entry.Level, "error")
		case 310, 311: // process_vm_readv, process_vm_writev
			entry.Level = elevate(entry.Level, "error")
		}

	case EventContainerEscape:
		entry.Message = fmt.Sprintf("Container escape attempt by %s (PID %d)", comm, event.PID)
		entry.Tags = append(entry.Tags, "container", "escape", "critical")
		entry.Level = "fatal"

	case EventCredChange:
		entry.Message = fmt.Sprintf("Credential change by %s (PID %d)", comm, event.PID)
		entry.Tags = append(entry.Tags, "cred_change")
		entry.Level = elevate(entry.Level, "warn")

	default:
		entry.Message = fmt.Sprintf("Security event from %s (PID %d)", comm, event.PID)
	}

	return entry
}

// elevate returns the higher severity of current and minimum.
// Severity order: debug < info < warn < error < fatal.
func elevate(current, minimum string) string {
	order := map[string]int{"debug": 0, "info": 1, "warn": 2, "error": 3, "fatal": 4}
	if order[minimum] > order[current] {
		return minimum
	}
	return current
}

// getEventLevel converts security level to log level
func (c *Collector) getEventLevel(securityLevel uint32) string {
	switch securityLevel {
	case SecurityLevelInfo:
		return "info"
	case SecurityLevelLow:
		return "debug"
	case SecurityLevelMedium:
		return "warn"
	case SecurityLevelHigh:
		return "error"
	case SecurityLevelCritical:
		return "fatal"
	default:
		return "info"
	}
}

// getEventTypeTag returns a tag for the event type
func (c *Collector) getEventTypeTag(eventType uint32) string {
	switch eventType {
	case EventProcessExec:
		return "process-exec"
	case EventNetworkConnect:
		return "network-connect"
	case EventFileAccess:
		return "file-access"
	case EventSyscallAnomaly:
		return "syscall-anomaly"
	case EventContainerEscape:
		return "container-escape"
	default:
		return "unknown-event"
	}
}

// getEBPFStats returns current eBPF statistics
func (c *Collector) getEBPFStats() map[string]interface{} {
	return c.ebpfManager.GetStats()
}

// getTLSCaptureStats returns TLS capture statistics, or nil if disabled.
func (c *Collector) getTLSCaptureStats() interface{} {
	if c.tlsCapture == nil {
		return map[string]interface{}{"enabled": false}
	}
	stats := c.tlsCapture.Stats()
	stats["enabled"] = true
	return stats
}

// getSecurityInfo returns security configuration information
func (c *Collector) getSecurityInfo() map[string]interface{} {
	return map[string]interface{}{
		"capabilities_verified":  true,
		"signature_verification": c.signatureManager.GetSigningInfo(),
		"input_validation":       "enabled",
		"rate_limiting":          "enabled",
		"audit_logging":          "enabled",
		"memory_protection":      "enabled",
	}
}

// sendBatch sends a log batch to the ingestion endpoint
func (c *Collector) sendBatch(payload ingestionRequest) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.Header.Set("User-Agent", "prysm-ebpf-collector/0.1")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("request rejected: status=%d", resp.StatusCode)
	}

	return nil
}

// evaluateRules runs an enriched event through the CEL rules engine.
func (c *Collector) evaluateRules(enriched EnrichedEvent) {
	// Derive parent name from ancestors.
	pname := ""
	if len(enriched.ProcAncestors) > 0 {
		pname = enriched.ProcAncestors[0]
	}

	// Extract file directory and name.
	fileDir, fileName := "", ""
	if enriched.FilePath != "" {
		fileDir = filepath.Dir(enriched.FilePath)
		fileName = filepath.Base(enriched.FilePath)
	}

	// Convert syscall args to uint64 slice.
	syscallArgs := make([]uint64, len(enriched.SyscallArgs))
	copy(syscallArgs, enriched.SyscallArgs[:])

	vars := rules.EventVars{
		EvtType:        enriched.EventType,
		EvtSource:      enriched.Source,
		ProcName:       enriched.ProcName,
		ProcCmdline:    enriched.ProcCmdline,
		ProcExePath:    enriched.ProcExePath,
		ProcPID:        uint64(enriched.ProcPID),
		ProcPPID:       uint64(enriched.ProcPPID),
		ProcUID:        uint64(enriched.ProcUID),
		ProcGID:        uint64(enriched.ProcGID),
		ProcAncestors:  enriched.ProcAncestors,
		ProcPName:      pname,
		ContainerID:    enriched.ContainerID,
		ContainerName:  enriched.ContainerName,
		ContainerImage: enriched.ContainerImage,
		K8sNS:          enriched.K8sNamespace,
		K8sPod:         enriched.K8sPod,
		K8sLabels:      enriched.K8sLabels,
		NetSrcIP:       enriched.NetSrcIP,
		NetDstIP:       enriched.NetDstIP,
		NetSrcPort:     uint64(enriched.NetSrcPort),
		NetDstPort:     uint64(enriched.NetDstPort),
		NetProtocol:    enriched.NetProtocol,
		NetDirection:   enriched.NetDirection,
		FilePath:       enriched.FilePath,
		FileFlags:      uint64(enriched.FileFlags),
		FileMode:       uint64(enriched.FileMode),
		FileDirectory:  fileDir,
		FileName:       fileName,
		SyscallNr:      enriched.SyscallNr,
		SyscallName:    enriched.SyscallName,
		SyscallArgs:    syscallArgs,
		CredOldUID:     uint64(enriched.CredOldUID),
		CredNewUID:     uint64(enriched.CredNewUID),
		CredOldGID:     uint64(enriched.CredOldGID),
		CredNewGID:     uint64(enriched.CredNewGID),
		TimestampNs:    enriched.Timestamp.UnixNano(),
	}

	c.rulesEngine.Evaluate(vars)
}

// handleRuleAlert processes an alert fired by the rules engine and sends it
// as a high-priority log entry.
func (c *Collector) handleRuleAlert(alert rules.Alert) {
	c.logger.Printf("RULE MATCH [%s/%s]: %s",
		alert.RuleName, alert.Priority, alert.Output)

	// Write to output sinks (file, stdout, syslog, etc.)
	if c.outputWriter != nil {
		outAlert := output.Alert{
			Timestamp: time.Now().UTC(),
			RuleName:  alert.RuleName,
			Output:    alert.Output,
			Priority:  alert.Priority.String(),
			Tags:      alert.Tags,
			Source:    alert.Source,
			Fields:    alert.Fields,
		}
		if err := c.outputWriter.WriteAlert(outAlert); err != nil {
			c.logEventErrorRateLimited("output_write", "output writer error: %v", err)
		}
	}

	level := "warn"
	switch {
	case alert.Priority >= rules.PriorityAlert:
		level = "fatal"
	case alert.Priority >= rules.PriorityCritical:
		level = "error"
	case alert.Priority >= rules.PriorityWarning:
		level = "warn"
	default:
		level = "info"
	}

	entry := logEntry{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Message:   alert.Output,
		Source:    "security",
		ClusterID: c.cfg.ClusterID,
		Node:      c.cfg.NodeName,
		Namespace: c.cfg.Namespace,
		Tags:      append([]string{"ebpf", "security", "rule_match"}, alert.Tags...),
		Metadata: map[string]any{
			"org_id":       c.cfg.OrgID,
			"sink_id":      c.cfg.SinkID,
			"rule_name":    alert.RuleName,
			"rule_priority": alert.Priority.String(),
			"rule_source":  alert.Source,
		},
	}

	if alert.Fields != nil {
		for k, v := range alert.Fields {
			entry.Metadata["rule_"+k] = v
		}
	}

	// Enqueue rule alert into batch sender
	c.batchSender.Enqueue(entry)
}

// nullTerminatedString converts a byte array to a null-terminated string
func nullTerminatedString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
