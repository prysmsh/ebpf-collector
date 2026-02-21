package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// Additional event type constants for process exit and credential change events.
const (
	EventProcessExit = 6
	EventCredChange  = 7
)

// EnrichedEvent wraps a raw eBPF SecurityEvent with process lineage,
// container metadata, and Kubernetes metadata. It is the universal input
// to the rules engine.
type EnrichedEvent struct {
	// RawEvent is the original eBPF security event.
	RawEvent SecurityEvent

	// Timestamp is the wall-clock time of the event.
	Timestamp time.Time

	// EventType is a human-readable event type string: "execve", "open",
	// "connect", "syscall", "cred_change", "exit".
	EventType string

	// Source identifies the event origin: "ebpf" or "k8s_audit".
	Source string

	// ---- Process fields ----

	ProcName      string   // comm
	ProcCmdline   string   // full cmdline (exec events)
	ProcExePath   string   // filename (exec events)
	ProcPID       uint32
	ProcPPID      uint32
	ProcUID       uint32
	ProcGID       uint32
	ProcAncestors []string // ancestor comm names from the process tree

	// ---- Container fields ----

	ContainerID    string
	ContainerName  string
	ContainerImage string

	// ---- Kubernetes fields ----

	K8sNamespace string
	K8sPod       string
	K8sLabels    map[string]string

	// ---- Network fields (populated for network events) ----

	NetSrcIP     string
	NetDstIP     string
	NetSrcPort   uint16
	NetDstPort   uint16
	NetProtocol  string
	NetDirection string // "outbound", "inbound", "listen"

	// ---- File fields (populated for file events) ----

	FilePath  string
	FileFlags uint32
	FileMode  uint32

	// ---- Syscall fields ----

	SyscallNr   uint64
	SyscallName string
	SyscallArgs [6]uint64

	// ---- Credential change fields ----

	CredOldUID uint32
	CredNewUID uint32
	CredOldGID uint32
	CredNewGID uint32

	// ---- TLS fields (populated for tls_data events) ----

	TLSDirection string // "outbound" or "inbound"
	TLSDataLen   uint32
}

// EventEnricher enriches raw SecurityEvents with process tree lineage and
// container/pod metadata to produce EnrichedEvents for the rules engine.
type EventEnricher struct {
	processTree       *ProcessTree
	containerEnricher *ContainerEnricher
}

// NewEventEnricher creates an EventEnricher that uses the supplied
// ProcessTree and ContainerEnricher to hydrate raw events.
func NewEventEnricher(pt *ProcessTree, ce *ContainerEnricher) *EventEnricher {
	return &EventEnricher{
		processTree:       pt,
		containerEnricher: ce,
	}
}

// Enrich converts a raw SecurityEvent into a fully enriched EnrichedEvent
// by parsing the event data union, walking the process tree for ancestor
// information, and looking up container/pod metadata.
func (e *EventEnricher) Enrich(event SecurityEvent) EnrichedEvent {
	comm := nullTerminatedString(event.Comm[:])
	containerID := nullTerminatedString(event.ContainerID[:])

	// Convert eBPF timestamp (nanoseconds since boot) to wall-clock time.
	// Fall back to current time when the kernel timestamp cannot be mapped.
	ts := time.Unix(0, int64(event.Timestamp))
	if event.Timestamp == 0 || ts.Year() < 2020 {
		ts = time.Now().UTC()
	}

	enriched := EnrichedEvent{
		RawEvent:    event,
		Timestamp:   ts,
		Source:      "ebpf",
		ProcName:    comm,
		ProcPID:     event.PID,
		ProcPPID:    event.PPID,
		ProcUID:     event.UID,
		ProcGID:     event.GID,
		ContainerID: containerID,
		K8sLabels:   make(map[string]string),
	}

	// Determine human-readable EventType and parse the data union.
	switch event.EventType {
	case EventProcessExec:
		enriched.EventType = "execve"
		e.parseExecData(&enriched, &event)

	case EventNetworkConnect:
		enriched.EventType = "connect"
		e.parseNetworkData(&enriched, &event)

	case EventFileAccess:
		enriched.EventType = "open"
		e.parseFileData(&enriched, &event)

	case EventSyscallAnomaly:
		enriched.EventType = "syscall"
		e.parseSyscallData(&enriched, &event)

	case EventContainerEscape:
		enriched.EventType = "syscall"

	case EventProcessExit:
		enriched.EventType = "exit"

	case EventCredChange:
		enriched.EventType = "cred_change"
		e.parseCredData(&enriched, &event)

	default:
		enriched.EventType = fmt.Sprintf("unknown_%d", event.EventType)
	}

	// Enrich with process tree lineage.
	if e.processTree != nil {
		enriched.ProcAncestors = e.processTree.GetAncestorComms(event.PID, 8)
	}

	// Enrich with container and Kubernetes metadata.
	if e.containerEnricher != nil {
		if info := e.containerEnricher.EnrichByPID(event.PID); info != nil {
			if enriched.ContainerID == "" {
				enriched.ContainerID = info.ContainerID
			}
			enriched.ContainerName = info.ContainerName
			enriched.ContainerImage = info.ImageName
			enriched.K8sNamespace = info.PodNamespace
			enriched.K8sPod = info.PodName
			if len(info.Labels) > 0 {
				enriched.K8sLabels = info.Labels
			}
		}
	}

	return enriched
}

// parseExecData extracts the filename and argv from the exec data union.
// Layout: filename[256] + argv[512]
func (e *EventEnricher) parseExecData(enriched *EnrichedEvent, event *SecurityEvent) {
	enriched.ProcExePath = nullTerminatedString(event.Data.Raw[0:256])
	enriched.ProcCmdline = nullTerminatedString(event.Data.Raw[256:768])
}

// parseNetworkData extracts address family, protocol, source/destination
// addresses and ports, and connection direction from the network data union.
// Layout: family(4) + type(4) + protocol(4) + src_addr(16) + dst_addr(16) +
//
//	src_port(2) + dst_port(2) + direction(1) ...
func (e *EventEnricher) parseNetworkData(enriched *EnrichedEvent, event *SecurityEvent) {
	data := event.Data.Raw[:]

	protocol := binary.LittleEndian.Uint32(data[8:12])
	switch protocol {
	case 6:
		enriched.NetProtocol = "tcp"
	case 17:
		enriched.NetProtocol = "udp"
	default:
		enriched.NetProtocol = fmt.Sprintf("proto_%d", protocol)
	}

	// Source and destination addresses are stored as 16-byte fields. For
	// IPv4 (AF_INET) the address occupies the first 4 bytes.
	srcAddr := binary.LittleEndian.Uint32(data[12:16])
	dstAddr := binary.LittleEndian.Uint32(data[28:32])

	enriched.NetSrcIP = net.IPv4(byte(srcAddr), byte(srcAddr>>8), byte(srcAddr>>16), byte(srcAddr>>24)).String()
	enriched.NetDstIP = net.IPv4(byte(dstAddr), byte(dstAddr>>8), byte(dstAddr>>16), byte(dstAddr>>24)).String()

	enriched.NetSrcPort = binary.LittleEndian.Uint16(data[44:46])
	enriched.NetDstPort = binary.LittleEndian.Uint16(data[46:48])

	// Direction byte at offset 48.
	switch data[48] {
	case 0:
		enriched.NetDirection = "outbound"
	case 1:
		enriched.NetDirection = "inbound"
	case 2:
		enriched.NetDirection = "listen"
	default:
		enriched.NetDirection = "outbound"
	}
}

// parseFileData extracts the filename, flags, and mode from the file data
// union. Layout: filename[256] + flags(4) + mode(4)
func (e *EventEnricher) parseFileData(enriched *EnrichedEvent, event *SecurityEvent) {
	enriched.FilePath = nullTerminatedString(event.Data.Raw[0:256])
	enriched.FileFlags = binary.LittleEndian.Uint32(event.Data.Raw[256:260])
	enriched.FileMode = binary.LittleEndian.Uint32(event.Data.Raw[260:264])
}

// parseSyscallData extracts the syscall number and arguments from the
// syscall data union. Layout: syscall_nr(8) + args[6](48)
func (e *EventEnricher) parseSyscallData(enriched *EnrichedEvent, event *SecurityEvent) {
	data := event.Data.Raw[:]
	enriched.SyscallNr = binary.LittleEndian.Uint64(data[0:8])
	for i := 0; i < 6; i++ {
		enriched.SyscallArgs[i] = binary.LittleEndian.Uint64(data[8+i*8 : 16+i*8])
	}
	enriched.SyscallName = SyscallName(enriched.SyscallNr)
}

// parseCredData extracts old/new UID and GID from the credential change
// data union. Layout: old_uid(4) + new_uid(4) + old_gid(4) + new_gid(4)
// (+ old_cap/new_cap at bytes 16-32, not exposed in EnrichedEvent).
func (e *EventEnricher) parseCredData(enriched *EnrichedEvent, event *SecurityEvent) {
	data := event.Data.Raw[:]
	enriched.CredOldUID = binary.LittleEndian.Uint32(data[0:4])
	enriched.CredNewUID = binary.LittleEndian.Uint32(data[4:8])
	enriched.CredOldGID = binary.LittleEndian.Uint32(data[8:12])
	enriched.CredNewGID = binary.LittleEndian.Uint32(data[12:16])
}
