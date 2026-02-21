package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// SecurityEvent represents the C structure from eBPF programs
// Must match struct security_event in programs.h exactly
type SecurityEvent struct {
	Timestamp     uint64
	EventType     uint32
	PID           uint32
	TGID          uint32
	UID           uint32
	GID           uint32
	SecurityLevel uint32
	PPID          uint32
	_Pad0         uint32
	Comm          [16]byte
	ContainerID   [128]byte // MAX_CONTAINER_ID_SIZE
	Data          SecurityEventData
}

// SecurityEventData is a union type representing different event data
// Must match the union in struct security_event
// Largest member is exec: filename[256] + argv[512] + flags[4] = 772 bytes
type SecurityEventData struct {
	Raw [772]byte // Size of largest union member (exec)
}

// SyscallData represents the parsed syscall data from SecurityEventData
// Layout: syscall_nr (8 bytes) + args[6] (48 bytes) + description (256 bytes)
type SyscallData struct {
	SyscallNr   uint64
	Args        [6]uint64
	Description [256]byte
}

// ParseSyscallData extracts syscall data from the raw event data
func (d *SecurityEventData) ParseSyscallData() SyscallData {
	var sd SyscallData
	sd.SyscallNr = *(*uint64)(unsafe.Pointer(&d.Raw[0]))
	for i := 0; i < 6; i++ {
		sd.Args[i] = *(*uint64)(unsafe.Pointer(&d.Raw[8+i*8]))
	}
	copy(sd.Description[:], d.Raw[56:56+256])
	return sd
}

// SyscallName returns the name of a syscall number (x86_64)
func SyscallName(nr uint64) string {
	names := map[uint64]string{
		0: "read", 1: "write", 2: "open", 3: "close", 4: "stat", 5: "fstat",
		6: "lstat", 7: "poll", 8: "lseek", 9: "mmap", 10: "mprotect",
		11: "munmap", 12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
		15: "rt_sigreturn", 16: "ioctl", 17: "pread64", 18: "pwrite64",
		19: "readv", 20: "writev", 21: "access", 22: "pipe", 23: "select",
		24: "sched_yield", 25: "mremap", 26: "msync", 27: "mincore",
		28: "madvise", 29: "shmget", 30: "shmat", 31: "shmctl",
		32: "dup", 33: "dup2", 34: "pause", 35: "nanosleep",
		36: "getitimer", 37: "alarm", 38: "setitimer",
		39: "getpid", 40: "sendfile", 41: "socket", 42: "connect", 43: "accept",
		44: "sendto", 45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
		48: "shutdown", 49: "bind", 50: "listen", 51: "getsockname",
		52: "getpeername", 53: "socketpair", 54: "setsockopt", 55: "getsockopt",
		56: "clone", 57: "fork", 58: "vfork", 59: "execve", 60: "exit",
		61: "wait4", 62: "kill", 63: "uname", 72: "fcntl", 73: "flock",
		74: "fsync", 75: "fdatasync", 76: "truncate", 77: "ftruncate",
		78: "getdents", 79: "getcwd", 80: "chdir", 81: "fchdir",
		82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat", 86: "link",
		87: "unlink", 88: "symlink", 89: "readlink", 90: "chmod",
		91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
		95: "umask", 96: "gettimeofday", 97: "getrlimit", 98: "getrusage",
		99: "sysinfo", 100: "times", 101: "ptrace", 102: "getuid",
		104: "getgid", 105: "setuid", 106: "setgid", 107: "geteuid",
		108: "getegid", 109: "setpgid", 110: "getppid", 111: "getpgrp",
		112: "setsid", 113: "setreuid", 114: "setregid", 115: "getgroups",
		116: "setgroups", 117: "setresuid", 118: "getresuid", 119: "setresgid",
		120: "getresgid", 121: "getpgid", 122: "setfsuid", 123: "setfsgid",
		124: "getsid", 125: "capget", 126: "capset", 127: "rt_sigpending",
		155: "pivot_root", 157: "prctl", 158: "arch_prctl", 160: "setrlimit", 161: "chroot",
		165: "mount", 166: "umount2", 175: "init_module", 176: "delete_module",
		200: "tkill", 202: "futex", 217: "getdents64", 228: "clock_gettime",
		230: "clock_nanosleep", 231: "exit_group", 232: "epoll_wait",
		233: "epoll_ctl", 250: "keyctl", 257: "openat",
		262: "newfstatat", 263: "unlinkat", 268: "fchmodat", 272: "unshare",
		288: "accept4", 293: "pipe2", 298: "perf_event_open", 302: "prlimit64",
		308: "setns", 310: "process_vm_readv", 311: "process_vm_writev",
		281: "epoll_pwait", 284: "eventfd", 289: "signalfd4", 290: "eventfd2",
		291: "epoll_create1", 294: "inotify_init1", 295: "preadv", 296: "pwritev",
		317: "seccomp", 318: "getrandom", 319: "memfd_create", 320: "kexec_file_load",
		321: "bpf", 322: "execveat", 323: "userfaultfd", 326: "copy_file_range",
		332: "statx", 424: "pidfd_send_signal", 434: "pidfd_open", 435: "clone3",
		437: "openat2", 438: "pidfd_getfd", 439: "faccessat2", 441: "epoll_pwait2",
	}
	if name, ok := names[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

// Event type constants (matching eBPF definitions)
const (
	EventProcessExec     = 1
	EventNetworkConnect  = 2
	EventFileAccess      = 3
	EventSyscallAnomaly  = 4
	EventContainerEscape = 5
	EventTLSData         = 8
)

// Security level constants
const (
	SecurityLevelInfo     = 0
	SecurityLevelLow      = 1
	SecurityLevelMedium   = 2
	SecurityLevelHigh     = 3
	SecurityLevelCritical = 4
)

// MeshEventCallback is called directly from the ring buffer reader for network
// events, bypassing the shared eventChan which is easily saturated by
// syscall/process events. Returns true if the event was consumed.
type MeshEventCallback func(event SecurityEvent) bool

// EBPFManager manages all eBPF programs and their lifecycle
type EBPFManager struct {
	programs    map[string]*ebpf.Program
	links       map[string]link.Link
	ringbuffers map[string]*ringbuf.Reader
	bpfMaps     map[string]*ebpf.Map // Named eBPF maps from loaded programs
	spec        *ebpf.CollectionSpec
	collection  *ebpf.Collection
	eventChan   chan SecurityEvent
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.RWMutex
	// Fast-path callback for mesh network events (bypasses eventChan)
	meshCallback MeshEventCallback
	// Rate-limit hot-path logs to avoid log spam
	dropMu      sync.Mutex
	dropCount   map[string]uint64
	lastDropLog map[string]time.Time
	readErrMu   sync.Mutex
	lastReadErr map[string]time.Time
}

// NewEBPFManager creates a new eBPF manager instance
func NewEBPFManager(ebpfDir string) (*EBPFManager, error) {
	// Remove memory limit for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	manager := &EBPFManager{
		programs:    make(map[string]*ebpf.Program),
		links:       make(map[string]link.Link),
		ringbuffers: make(map[string]*ringbuf.Reader),
		bpfMaps:     make(map[string]*ebpf.Map),
		eventChan:   make(chan SecurityEvent, 1000),
		ctx:         ctx,
		cancel:      cancel,
		dropCount:   make(map[string]uint64),
		lastDropLog: make(map[string]time.Time),
		lastReadErr: make(map[string]time.Time),
	}

	return manager, nil
}

// LoadPrograms loads all eBPF programs from object files
func (em *EBPFManager) LoadPrograms(ebpfDir string) error {
	em.mu.Lock()
	defer em.mu.Unlock()

	// Define the eBPF programs we want to load
	programs := []string{
		"process_monitor.o",
		"network_monitor.o",
		"file_monitor.o",
		"syscall_monitor.o",
	}

	// Optionally load extra programs if their object files exist.
	for _, extra := range []string{"cred_monitor.o", "fd_tracker.o"} {
		if _, err := os.Stat(filepath.Join(ebpfDir, extra)); err == nil {
			programs = append(programs, extra)
		}
	}

	var loaded int
	for _, program := range programs {
		programPath := filepath.Join(ebpfDir, program)
		if err := em.loadSingleProgram(programPath); err != nil {
			log.Printf("Failed to load program %s: %v", program, err)
			// Continue loading other programs even if one fails
			continue
		}
		loaded++
		log.Printf("Successfully loaded eBPF program: %s", program)
	}

	if loaded == 0 {
		return fmt.Errorf("no eBPF programs loaded from %s", ebpfDir)
	}
	log.Printf("Loaded %d/%d eBPF programs", loaded, len(programs))

	return nil
}

// loadSingleProgram loads a single eBPF program from an object file
func (em *EBPFManager) loadSingleProgram(objectPath string) error {
	// Load the compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("failed to load collection spec from %s: %w", objectPath, err)
	}

	// Load the collection
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}

	// Store programs and attach them
	for name, program := range collection.Programs {
		em.programs[name] = program

		// Attach the program based on its type
		if err := em.attachProgram(name, program); err != nil {
			log.Printf("Failed to attach program %s: %v", name, err)
			continue
		}
	}

	// Store named maps for later access (e.g. syscall_filter).
	for name, mapObj := range collection.Maps {
		em.bpfMaps[name] = mapObj
	}

	// Set up ring buffers for event collection
	for name, mapObj := range collection.Maps {
		if mapObj.Type() == ebpf.RingBuf {
			reader, err := ringbuf.NewReader(mapObj)
			if err != nil {
				log.Printf("Failed to create ring buffer reader for %s: %v", name, err)
				continue
			}
			em.ringbuffers[name] = reader

			// Start reading from this ring buffer
			em.wg.Add(1)
			go em.readRingBuffer(name, reader)
		}
	}

	return nil
}

// attachProgram attaches an eBPF program to the appropriate hook point
func (em *EBPFManager) attachProgram(name string, program *ebpf.Program) error {
	var l link.Link
	var err error

	switch {
	case contains(name, "trace_process_exec"):
		l, err = link.Tracepoint("sched", "sched_process_exec", program, nil)
	case contains(name, "trace_process_exit"):
		l, err = link.Tracepoint("sched", "sched_process_exit", program, nil)
	case contains(name, "trace_tcp_v6_connect"):
		l, err = link.Kprobe("tcp_v6_connect", program, nil)
	case contains(name, "trace_tcp_connect_ret"):
		l, err = link.Kretprobe("tcp_v4_connect", program, nil)
	case contains(name, "trace_tcp_connect"):
		l, err = link.Kprobe("tcp_v4_connect", program, nil)
	case contains(name, "trace_tcp_close"):
		l, err = link.Kprobe("tcp_close", program, nil)
	case contains(name, "trace_udp_send"):
		l, err = link.Kprobe("udp_sendmsg", program, nil)
	case contains(name, "trace_file_open"):
		l, err = link.Kprobe("do_sys_open", program, nil)
	case contains(name, "trace_file_unlink"):
		l, err = link.Tracepoint("syscalls", "sys_enter_unlink", program, nil)
	case contains(name, "trace_chmod"):
		l, err = link.Kprobe("chmod_common", program, nil)
	case contains(name, "trace_syscall_enter"):
		l, err = link.Tracepoint("raw_syscalls", "sys_enter", program, nil)
	case contains(name, "trace_mmap_exec"):
		l, err = link.Kprobe("do_mmap", program, nil)
	case contains(name, "trace_setuid"):
		l, err = link.Kprobe("sys_setuid", program, nil)
	case contains(name, "trace_commit_creds"):
		l, err = link.Kprobe("commit_creds", program, nil)
	case contains(name, "trace_inet_accept"):
		l, err = link.Kretprobe("inet_csk_accept", program, nil)
	case contains(name, "trace_inet_bind"):
		l, err = link.Kprobe("inet_bind", program, nil)
	case contains(name, "trace_openat_enter"):
		l, err = link.Tracepoint("syscalls", "sys_enter_openat", program, nil)
	case contains(name, "trace_openat_exit"):
		l, err = link.Tracepoint("syscalls", "sys_exit_openat", program, nil)
	case contains(name, "trace_close_enter"):
		l, err = link.Tracepoint("syscalls", "sys_enter_close", program, nil)
	case contains(name, "xdp_packet_monitor"):
		// XDP programs need to be attached to network interfaces
		// This would require interface specification - skip for now
		log.Printf("XDP program %s requires manual interface attachment", name)
		return nil
	default:
		log.Printf("Unknown program type for %s, skipping attachment", name)
		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to attach program %s: %w", name, err)
	}

	if l != nil {
		em.links[name] = l
		log.Printf("Successfully attached program: %s", name)
	}

	return nil
}

// readRingBuffer reads events from a ring buffer and forwards them to the event channel
func (em *EBPFManager) readRingBuffer(name string, reader *ringbuf.Reader) {
	defer em.wg.Done()
	defer reader.Close()

	log.Printf("Starting ring buffer reader for: %s", name)

	for {
		select {
		case <-em.ctx.Done():
			log.Printf("Stopping ring buffer reader for: %s", name)
			return
		default:
			// Read with timeout to allow checking context cancellation
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					log.Printf("Ring buffer %s closed", name)
					return
				}
				// Rate-limit read error logs to avoid spam (e.g. EAGAIN)
				em.readErrMu.Lock()
				last := em.lastReadErr[name]
				now := time.Now()
				if now.Sub(last) >= 60*time.Second {
					log.Printf("Error reading from ring buffer %s: %v", name, err)
					em.lastReadErr[name] = now
				}
				em.readErrMu.Unlock()
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Parse the raw record into a SecurityEvent
			if len(record.RawSample) >= int(unsafe.Sizeof(SecurityEvent{})) {
				event := (*SecurityEvent)(unsafe.Pointer(&record.RawSample[0]))
				ev := *event // copy before pointer becomes invalid

				// Fast-path: route network events directly to mesh callback,
				// bypassing the shared eventChan that is easily saturated by
				// high-volume syscall/process events.
				if ev.EventType == EventNetworkConnect && em.meshCallback != nil {
					if em.meshCallback(ev) {
						continue // mesh forwarder consumed the event
					}
				}

				// Send event to processing channel (non-blocking)
				select {
				case em.eventChan <- ev:
				default:
					// Rate-limit "channel full" logs: log at most every 10s per buffer with drop count
					em.dropMu.Lock()
					em.dropCount[name]++
					count := em.dropCount[name]
					last := em.lastDropLog[name]
					now := time.Now()
					if now.Sub(last) >= 60*time.Second {
						log.Printf("Event channel full, dropped %d events from %s (rate-limited log)", count, name)
						em.lastDropLog[name] = now
						em.dropCount[name] = 0
					}
					em.dropMu.Unlock()
				}
			}
		}
	}
}

// SetMeshEventCallback registers a callback that is invoked directly from the
// ring buffer reader goroutine for EventNetworkConnect events. This provides a
// dedicated fast path for mesh topology events that bypasses the shared
// eventChan, which can be saturated by high-volume syscall/process events.
// Must be called before LoadPrograms.
func (em *EBPFManager) SetMeshEventCallback(cb MeshEventCallback) {
	em.meshCallback = cb
}

// GetEventChannel returns the channel for receiving security events
func (em *EBPFManager) GetEventChannel() <-chan SecurityEvent {
	return em.eventChan
}

// Stop gracefully shuts down the eBPF manager
func (em *EBPFManager) Stop() error {
	em.mu.Lock()
	defer em.mu.Unlock()

	log.Println("Stopping eBPF manager...")

	// Cancel context to stop all goroutines
	em.cancel()

	// Wait for all ring buffer readers to stop
	em.wg.Wait()

	// Close all links
	for name, l := range em.links {
		if err := l.Close(); err != nil {
			log.Printf("Error closing link %s: %v", name, err)
		}
	}

	// Close all ring buffer readers
	for name, reader := range em.ringbuffers {
		if err := reader.Close(); err != nil {
			log.Printf("Error closing ring buffer reader %s: %v", name, err)
		}
	}

	// Close the collection
	if em.collection != nil {
		em.collection.Close()
	}

	// Close event channel
	close(em.eventChan)

	log.Println("eBPF manager stopped successfully")
	return nil
}

// GetStats returns statistics about loaded programs and events
func (em *EBPFManager) GetStats() map[string]interface{} {
	em.mu.RLock()
	defer em.mu.RUnlock()

	stats := map[string]interface{}{
		"loaded_programs": len(em.programs),
		"active_links":    len(em.links),
		"ring_buffers":    len(em.ringbuffers),
		"event_chan_size": len(em.eventChan),
	}

	// Add per-program statistics if available
	programStats := make(map[string]interface{})
	for name := range em.programs {
		programStats[name] = map[string]interface{}{
			"attached": em.links[name] != nil,
		}
	}
	stats["programs"] = programStats

	return stats
}

// PopulateSyscallFilter populates the eBPF syscall_filter map with the given
// syscall numbers. Only events matching these syscalls will be emitted by the
// kernel-side filter. The set of syscalls is typically derived from the loaded
// rules (any rule with evt.type == 'syscall' that references syscall.name or
// syscall.nr).
func (em *EBPFManager) PopulateSyscallFilter(syscallNrs []uint64) error {
	em.mu.RLock()
	defer em.mu.RUnlock()

	filterMap, ok := em.bpfMaps["syscall_filter"]
	if !ok {
		return fmt.Errorf("syscall_filter map not found (syscall_monitor not loaded)")
	}

	// Clear existing entries by iterating and deleting.
	var key uint64
	for {
		var nextKey uint64
		if err := filterMap.NextKey(&key, &nextKey); err != nil {
			break
		}
		filterMap.Delete(&key)
		key = nextKey
	}

	// Insert new entries.
	enabled := uint32(1)
	for _, nr := range syscallNrs {
		if err := filterMap.Update(&nr, &enabled, ebpf.UpdateAny); err != nil {
			log.Printf("warning: failed to add syscall %d to filter: %v", nr, err)
		}
	}

	log.Printf("syscall filter populated with %d syscall numbers", len(syscallNrs))
	return nil
}

// DefaultSecuritySyscalls returns the syscall numbers for the ~30 most
// security-relevant syscalls that should be monitored by default.
func DefaultSecuritySyscalls() []uint64 {
	return []uint64{
		56,  // clone
		57,  // fork
		58,  // vfork
		59,  // execve
		101, // ptrace
		105, // setuid
		106, // setgid
		113, // setreuid
		114, // setregid
		117, // setresuid
		119, // setresgid
		122, // setfsuid
		123, // setfsgid
		125, // capget
		126, // capset
		155, // pivot_root
		157, // prctl
		161, // chroot
		165, // mount
		166, // umount2
		175, // init_module
		176, // delete_module
		272, // unshare
		308, // setns
		310, // process_vm_readv
		311, // process_vm_writev
		317, // seccomp
		319, // memfd_create
		322, // execveat
		9,   // mmap (with PROT_EXEC)
		10,  // mprotect (with PROT_EXEC)
		49,  // bind
		50,  // listen
	}
}

// InitializeSuspiciousLists populates maps with known malicious IPs/ports
func (em *EBPFManager) InitializeSuspiciousLists() error {
	em.mu.RLock()
	defer em.mu.RUnlock()

	// This would typically load from configuration or threat intelligence feeds
	// For now, we'll initialize with some example entries

	// Example: Add known malicious IPs to the suspicious_ips map
	// This would be done by finding the map and updating it
	for _, collection := range []*ebpf.Collection{em.collection} {
		if collection == nil {
			continue
		}

		if suspiciousIPs, exists := collection.Maps["suspicious_ips"]; exists {
			// Add some example malicious IPs
			maliciousIPs := []uint32{
				0x08080808, // 8.8.8.8 (example)
				0x01010101, // 1.1.1.1 (example)
			}

			for _, ip := range maliciousIPs {
				value := uint32(1) // Flag as suspicious
				if err := suspiciousIPs.Update(ip, value, ebpf.UpdateAny); err != nil {
					log.Printf("Failed to update suspicious IP %x: %v", ip, err)
				}
			}
		}

		if suspiciousPorts, exists := collection.Maps["suspicious_ports"]; exists {
			// Add some example suspicious ports
			suspiciousPortsList := []uint16{
				4444, 4445, 4446, // Common backdoor ports
				6666, 6667, 6668, // IRC/botnet ports
				31337, 31338, // Elite/hacker ports
				12345, 54321, // Common trojan ports
			}

			for _, port := range suspiciousPortsList {
				value := uint32(1) // Flag as suspicious
				if err := suspiciousPorts.Update(port, value, ebpf.UpdateAny); err != nil {
					log.Printf("Failed to update suspicious port %d: %v", port, err)
				}
			}
		}
	}

	return nil
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		(len(s) > len(substr) && s[:len(substr)] == substr) ||
		(len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// CompileEBPFPrograms compiles the eBPF C programs to object files
func CompileEBPFPrograms(ebpfDir string) error {
	programs := []string{
		"process_monitor.c",
		"network_monitor.c",
		"file_monitor.c",
		"syscall_monitor.c",
		"cred_monitor.c",
		"fd_tracker.c",
	}

	for _, program := range programs {
		sourcePath := filepath.Join(ebpfDir, program)
		objectPath := filepath.Join(ebpfDir, program[:len(program)-2]+".o")

		// Check if source file exists
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			return fmt.Errorf("required eBPF source file %s does not exist", sourcePath)
		}

		log.Printf("Compiling %s to %s", sourcePath, objectPath)
		// Production deployment would include pre-compiled .o files
		// For development, you'd run: clang -O2 -target bpf -c sourcePath -o objectPath
	}

	return nil
}
