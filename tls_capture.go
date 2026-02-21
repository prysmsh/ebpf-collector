package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/ringbuf"

	"ebpf-collector/output"
	"ebpf-collector/rules"
)

const (
	// Default values for TLS capture configuration.
	defaultTLSMaxData   = 4096
	defaultTLSRateLimit = 100
	tlsScanInterval     = 30 * time.Second
)

// TLSCaptureConfig holds configuration for TLS plaintext interception.
type TLSCaptureConfig struct {
	MaxDataSize int      // max bytes to capture per SSL_read/write
	RateLimit   int      // max captures per PID per second
	SkipComms   []string // process names to skip
}

// TLSDataEvent represents a parsed TLS data event from the ring buffer.
// Must match struct tls_data_event in programs.h.
type TLSDataEvent struct {
	Timestamp uint64
	PID       uint32
	TGID      uint32
	UID       uint32
	GID       uint32
	PPID      uint32
	DataLen   uint32
	Direction uint8  // 0=write/outbound, 1=read/inbound
	_Pad      [3]byte
	FD        uint32
	Comm      [16]byte
	Data      [4096]byte
}

// TLSCapture manages the TLS plaintext interception pipeline: library
// scanning, uprobe management, ring buffer reading, and DLP/threat inspection.
type TLSCapture struct {
	cfg               TLSCaptureConfig
	scanner           *TLSLibraryScanner
	uprobeManager     *TLSUprobeManager
	processTree       *ProcessTree
	containerEnricher *ContainerEnricher
	rulesEngine       *rules.Engine
	dlpMatcher        *TLSDLPMatcher
	outputWriter      output.Writer
	logger            *log.Logger

	eventsReceived atomic.Int64
	bytesCapture   atomic.Int64
	dlpAlerts      atomic.Int64
	alertCallback  func(ThreatDetection)
}

// NewTLSCapture constructs a TLS capture pipeline. It returns nil if the
// required eBPF object (tls_monitor.o) is not available.
func NewTLSCapture(
	collectorCfg Config,
	logger *log.Logger,
	processTree *ProcessTree,
	containerEnricher *ContainerEnricher,
	rulesEngine *rules.Engine,
	outputWriter output.Writer,
	alertCallback func(ThreatDetection),
) *TLSCapture {
	tlsCfg := parseTLSConfig()

	ebpfDir := os.Getenv("PRYSM_EBPF_ASSET_DIR")
	if ebpfDir == "" {
		ebpfDir = "./ebpf"
	}

	uprobeManager, err := NewTLSUprobeManager(ebpfDir, logger)
	if err != nil {
		logger.Printf("tls-capture: uprobe manager init failed (TLS interception disabled): %v", err)
		return nil
	}

	scanner := NewTLSLibraryScanner(collectorCfg.ProcRoot, tlsCfg.SkipComms, logger)

	return &TLSCapture{
		cfg:               tlsCfg,
		scanner:           scanner,
		uprobeManager:     uprobeManager,
		processTree:       processTree,
		containerEnricher: containerEnricher,
		rulesEngine:       rulesEngine,
		dlpMatcher:        NewTLSDLPMatcher(),
		outputWriter:      outputWriter,
		logger:            logger,
		alertCallback:     alertCallback,
	}
}

// Start begins library scanning, uprobe attachment, and ring buffer reading.
// It blocks until ctx is cancelled.
func (tc *TLSCapture) Start(ctx context.Context) {
	tc.logger.Println("tls-capture: starting TLS plaintext interception")

	// Start ring buffer reader in background.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tc.readTLSEvents(ctx)
	}()

	// Run periodic library scanning with uprobe reconciliation.
	stopCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopCh)
	}()

	tc.scanner.RunPeriodicScan(tlsScanInterval, stopCh, func(libs []*TLSLibrary) {
		tc.logger.Printf("tls-capture: discovered %d TLS libraries, reconciling uprobes", len(libs))
		tc.uprobeManager.Reconcile(libs)
		tc.logger.Printf("tls-capture: %d libraries attached", tc.uprobeManager.AttachedCount())
	})

	wg.Wait()
	tc.logger.Println("tls-capture: stopped")
}

// readTLSEvents reads from the dedicated TLS ring buffer and processes events.
func (tc *TLSCapture) readTLSEvents(ctx context.Context) {
	coll := tc.uprobeManager.Collection()
	if coll == nil {
		return
	}

	tlsEventsMap := coll.Maps["tls_events"]
	if tlsEventsMap == nil {
		tc.logger.Println("tls-capture: tls_events map not found in collection")
		return
	}

	reader, err := ringbuf.NewReader(tlsEventsMap)
	if err != nil {
		tc.logger.Printf("tls-capture: failed to create ring buffer reader: %v", err)
		return
	}
	defer reader.Close()

	// Close reader when context is cancelled.
	go func() {
		<-ctx.Done()
		reader.Close()
	}()

	tc.logger.Println("tls-capture: ring buffer reader started")

	for {
		record, err := reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if len(record.RawSample) < int(unsafe.Sizeof(TLSDataEvent{})) {
			continue
		}

		evt := (*TLSDataEvent)(unsafe.Pointer(&record.RawSample[0]))
		tc.processEvent(evt)
	}
}

// processEvent handles a single TLS data event: enriches it, runs DLP, and
// optionally feeds the rules engine.
func (tc *TLSCapture) processEvent(evt *TLSDataEvent) {
	tc.eventsReceived.Add(1)

	dataLen := evt.DataLen
	if dataLen > 4096 {
		dataLen = 4096
	}
	if dataLen == 0 {
		return
	}

	tc.bytesCapture.Add(int64(dataLen))

	data := evt.Data[:dataLen]
	comm := nullTerminatedString(evt.Comm[:])

	direction := "outbound"
	if evt.Direction == 1 {
		direction = "inbound"
	}

	// Run DLP pattern matching on plaintext.
	dlpMatches := tc.dlpMatcher.Scan(data)
	for _, m := range dlpMatches {
		tc.dlpAlerts.Add(1)
		tc.logger.Printf("tls-capture: DLP ALERT [%s] %s from %s (PID %d) direction=%s",
			m.Level, m.PatternName, comm, evt.PID, direction)

		// Emit as output alert.
		if tc.outputWriter != nil {
			outAlert := output.Alert{
				Timestamp: time.Now().UTC(),
				RuleName:  "tls_dlp_" + m.PatternID,
				Output:    m.Description + " (indicator: " + m.Redacted + ")",
				Priority:  m.Level,
				Tags:      []string{"tls", "dlp", m.PatternID},
				Source:    "tls_capture",
				Fields: map[string]string{
					"pid":        fmt.Sprintf("%d", evt.PID),
					"comm":       comm,
					"direction":  direction,
					"pattern_id": m.PatternID,
					"score":      fmt.Sprintf("%d", m.Score),
					"mitre":      m.MitreATTCK,
				},
			}
			if err := tc.outputWriter.WriteAlert(outAlert); err != nil {
				tc.logger.Printf("tls-capture: output write error: %v", err)
			}
		}

		// Emit as threat detection to the collector's alert pipeline.
		if tc.alertCallback != nil {
			processInfo := &ProcessContext{
				PID:  evt.PID,
				PPID: evt.PPID,
				UID:  evt.UID,
				Comm: comm,
			}

			// Enrich with process tree.
			if tc.processTree != nil {
				processInfo.Ancestors = tc.processTree.GetAncestorComms(evt.PID, 4)
			}

			// Enrich with container info.
			if tc.containerEnricher != nil {
				if info := tc.containerEnricher.EnrichByPID(evt.PID); info != nil {
					processInfo.ContainerID = info.ContainerID
				}
			}

			tc.alertCallback(ThreatDetection{
				Timestamp:   time.Now().UTC(),
				Category:    ThreatCategory("data_loss_prevention"),
				Level:       parseThreatLevel(m.Level),
				Score:       m.Score,
				Description: m.Description + " (via TLS interception, indicator: " + m.Redacted + ")",
				Indicators:  []string{m.PatternID, m.Redacted, "direction:" + direction},
				MitreATTCK:  m.MitreATTCK,
				ProcessInfo: processInfo,
			})
		}
	}

	// Feed rules engine with TLS event if configured.
	if tc.rulesEngine != nil {
		vars := rules.EventVars{
			EvtType:     "tls_data",
			EvtSource:   "tls_capture",
			ProcName:    comm,
			ProcPID:     uint64(evt.PID),
			ProcPPID:    uint64(evt.PPID),
			ProcUID:     uint64(evt.UID),
			ProcGID:     uint64(evt.GID),
			TimestampNs: int64(evt.Timestamp),
		}

		// Add container/K8s metadata.
		if tc.containerEnricher != nil {
			if info := tc.containerEnricher.EnrichByPID(evt.PID); info != nil {
				vars.ContainerID = info.ContainerID
				vars.ContainerName = info.ContainerName
				vars.K8sNS = info.PodNamespace
				vars.K8sPod = info.PodName
			}
		}

		// Add process ancestors.
		if tc.processTree != nil {
			vars.ProcAncestors = tc.processTree.GetAncestorComms(evt.PID, 8)
			if len(vars.ProcAncestors) > 0 {
				vars.ProcPName = vars.ProcAncestors[0]
			}
		}

		// Add TLS-specific fields.
		vars.NetDirection = direction
		vars.TLSDataLen = uint64(dataLen)

		tc.rulesEngine.Evaluate(vars)
	}
}

// parseThreatLevel converts a string level to a ThreatLevel constant.
func parseThreatLevel(level string) ThreatLevel {
	switch level {
	case "critical":
		return ThreatCritical
	case "high":
		return ThreatHigh
	case "medium":
		return ThreatMedium
	default:
		return ThreatLow
	}
}

// Stats returns TLS capture statistics.
func (tc *TLSCapture) Stats() map[string]interface{} {
	dlpScans, dlpMatches := tc.dlpMatcher.Stats()
	return map[string]interface{}{
		"events_received":  tc.eventsReceived.Load(),
		"bytes_captured":   tc.bytesCapture.Load(),
		"dlp_alerts":       tc.dlpAlerts.Load(),
		"dlp_scans":        dlpScans,
		"dlp_matches":      dlpMatches,
		"libraries_attached": tc.uprobeManager.AttachedCount(),
	}
}

// Close shuts down the TLS capture pipeline.
func (tc *TLSCapture) Close() {
	if tc.uprobeManager != nil {
		tc.uprobeManager.Close()
	}
}

// parseTLSConfig reads TLS capture configuration from environment variables.
func parseTLSConfig() TLSCaptureConfig {
	cfg := TLSCaptureConfig{
		MaxDataSize: defaultTLSMaxData,
		RateLimit:   defaultTLSRateLimit,
	}

	if v := os.Getenv("PRYSM_TLS_MAX_DATA"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 16384 {
			cfg.MaxDataSize = n
		}
	}

	if v := os.Getenv("PRYSM_TLS_RATE_LIMIT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.RateLimit = n
		}
	}

	if v := os.Getenv("PRYSM_TLS_SKIP_COMMS"); v != "" {
		for _, c := range strings.Split(v, ",") {
			c = strings.TrimSpace(c)
			if c != "" {
				cfg.SkipComms = append(cfg.SkipComms, c)
			}
		}
	}

	return cfg
}

// Ensure binary package is used (for data parsing).
var _ = binary.LittleEndian
