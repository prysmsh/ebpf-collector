package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProcessEntry represents a single process in the process tree.
type ProcessEntry struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	Comm        string
	Cmdline     string
	ContainerID string
	StartTime   time.Time
	ExitTime    time.Time // zero value means process is still alive
	Children    []uint32
}

// IsAlive returns true if the process has not exited.
func (pe *ProcessEntry) IsAlive() bool {
	return pe.ExitTime.IsZero()
}

// ProcessTree tracks process lineage for security analysis. It maintains a
// map of processes keyed by PID, supports ancestor chain lookups, and
// automatically cleans up dead processes after a configurable TTL.
type ProcessTree struct {
	mu        sync.RWMutex
	processes map[uint32]*ProcessEntry
	ttl       time.Duration
}

// NewProcessTree creates a new ProcessTree, bootstraps it from /proc (or
// HOST_PROC), and starts a background goroutine that periodically evicts
// dead processes whose exit time exceeds the TTL.
func NewProcessTree() *ProcessTree {
	pt := &ProcessTree{
		processes: make(map[uint32]*ProcessEntry),
		ttl:       5 * time.Minute,
	}

	// Determine proc root: respect HOST_PROC for containerized environments
	// where the host /proc is mounted at an alternate path.
	procRoot := strings.TrimSpace(os.Getenv("HOST_PROC"))
	if procRoot == "" {
		procRoot = "/proc"
	}
	procRoot = strings.TrimSuffix(procRoot, "/")

	pt.Bootstrap(procRoot)

	go pt.cleanup()

	return pt
}

// Bootstrap scans procRoot for existing processes and populates the tree.
// It reads /proc/*/status to extract Pid, PPid, Uid, and Name fields,
// and /proc/*/cmdline for the full command line.
func (pt *ProcessTree) Bootstrap(procRoot string) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		log.Printf("[process-tree] failed to read %s: %v", procRoot, err)
		return
	}

	pt.mu.Lock()
	defer pt.mu.Unlock()

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}

		pe := pt.parseStatus(procRoot, uint32(pid))
		if pe == nil {
			continue
		}

		// Read cmdline
		cmdlinePath := filepath.Join(procRoot, entry.Name(), "cmdline")
		if data, err := os.ReadFile(cmdlinePath); err == nil && len(data) > 0 {
			// cmdline uses null bytes as separators between arguments
			pe.Cmdline = strings.ReplaceAll(string(data), "\x00", " ")
			pe.Cmdline = strings.TrimSpace(pe.Cmdline)
		}

		pt.processes[pe.PID] = pe
	}

	// Second pass: populate Children slices now that all processes are loaded.
	for _, pe := range pt.processes {
		if parent, ok := pt.processes[pe.PPID]; ok && pe.PID != pe.PPID {
			parent.Children = append(parent.Children, pe.PID)
		}
	}

	log.Printf("[process-tree] bootstrapped %d processes from %s", len(pt.processes), procRoot)
}

// parseStatus reads /proc/<pid>/status and extracts process metadata.
func (pt *ProcessTree) parseStatus(procRoot string, pid uint32) *ProcessEntry {
	statusPath := filepath.Join(procRoot, fmt.Sprintf("%d", pid), "status")
	f, err := os.Open(statusPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	pe := &ProcessEntry{
		PID:       pid,
		StartTime: time.Now(), // Approximate; real start time would require /proc/<pid>/stat parsing
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Pid:"):
			if v, err := strconv.ParseUint(strings.TrimSpace(line[4:]), 10, 32); err == nil {
				pe.PID = uint32(v)
			}
		case strings.HasPrefix(line, "PPid:"):
			if v, err := strconv.ParseUint(strings.TrimSpace(line[5:]), 10, 32); err == nil {
				pe.PPID = uint32(v)
			}
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line[4:])
			if len(fields) > 0 {
				if v, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					pe.UID = uint32(v)
				}
			}
		case strings.HasPrefix(line, "Gid:"):
			fields := strings.Fields(line[4:])
			if len(fields) > 0 {
				if v, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					pe.GID = uint32(v)
				}
			}
		case strings.HasPrefix(line, "Name:"):
			pe.Comm = strings.TrimSpace(line[5:])
		}
	}

	return pe
}

// HandleExec adds or updates a process entry in the tree when a process
// exec event is observed. It also registers the process as a child of its
// parent if the parent exists in the tree.
func (pt *ProcessTree) HandleExec(pid, ppid, uid, gid uint32, comm, cmdline, containerID string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pe := &ProcessEntry{
		PID:         pid,
		PPID:        ppid,
		UID:         uid,
		GID:         gid,
		Comm:        comm,
		Cmdline:     cmdline,
		ContainerID: containerID,
		StartTime:   time.Now(),
	}

	// If there was a previous entry for this PID, remove it from its old parent's children list
	if old, exists := pt.processes[pid]; exists && old.PPID != ppid {
		pt.removeChild(old.PPID, pid)
	}

	pt.processes[pid] = pe

	// Register as child of parent
	if parent, ok := pt.processes[ppid]; ok && pid != ppid {
		// Avoid duplicate children entries
		found := false
		for _, childPID := range parent.Children {
			if childPID == pid {
				found = true
				break
			}
		}
		if !found {
			parent.Children = append(parent.Children, pid)
		}
	}
}

// HandleExit marks a process as exited by setting its ExitTime. The entry
// is not removed immediately; the background cleanup goroutine will evict
// it after the TTL expires.
func (pt *ProcessTree) HandleExit(pid uint32) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	if pe, ok := pt.processes[pid]; ok {
		pe.ExitTime = time.Now()
	}
}

// GetEntry returns a copy of the ProcessEntry for the given PID, or nil if
// the PID is not tracked.
func (pt *ProcessTree) GetEntry(pid uint32) *ProcessEntry {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	pe, ok := pt.processes[pid]
	if !ok {
		return nil
	}

	// Return a copy to avoid races on the caller side
	entry := *pe
	entry.Children = make([]uint32, len(pe.Children))
	copy(entry.Children, pe.Children)
	return &entry
}

// GetAncestorChain walks up the parent chain starting from pid and returns
// a slice of ProcessEntry copies ordered from the given process to the
// root. maxDepth caps the walk to prevent infinite loops from PID reuse
// or circular references; if maxDepth is <= 0 or > 10, it defaults to 10.
func (pt *ProcessTree) GetAncestorChain(pid uint32, maxDepth int) []ProcessEntry {
	if maxDepth <= 0 || maxDepth > 10 {
		maxDepth = 10
	}

	pt.mu.RLock()
	defer pt.mu.RUnlock()

	chain := make([]ProcessEntry, 0, maxDepth)
	visited := make(map[uint32]bool, maxDepth)
	current := pid

	for i := 0; i < maxDepth; i++ {
		if visited[current] {
			break // cycle detected
		}
		visited[current] = true

		pe, ok := pt.processes[current]
		if !ok {
			break
		}

		chain = append(chain, *pe)

		// PID 0 and 1 are root; stop walking
		if pe.PPID == 0 || pe.PPID == current {
			break
		}

		current = pe.PPID
	}

	return chain
}

// GetAncestorComms is a convenience method that returns just the Comm
// (process name) for each ancestor in the chain.
func (pt *ProcessTree) GetAncestorComms(pid uint32, maxDepth int) []string {
	chain := pt.GetAncestorChain(pid, maxDepth)
	comms := make([]string, len(chain))
	for i, pe := range chain {
		comms[i] = pe.Comm
	}
	return comms
}

// removeChild removes childPID from the Children slice of parentPID.
// Caller must hold pt.mu.
func (pt *ProcessTree) removeChild(parentPID, childPID uint32) {
	parent, ok := pt.processes[parentPID]
	if !ok {
		return
	}
	for i, c := range parent.Children {
		if c == childPID {
			parent.Children = append(parent.Children[:i], parent.Children[i+1:]...)
			return
		}
	}
}

// cleanup runs in a background goroutine and periodically removes dead
// processes whose ExitTime is older than the configured TTL.
func (pt *ProcessTree) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		pt.mu.Lock()
		now := time.Now()
		for pid, pe := range pt.processes {
			if !pe.ExitTime.IsZero() && now.Sub(pe.ExitTime) > pt.ttl {
				// Remove from parent's children list
				pt.removeChild(pe.PPID, pid)
				delete(pt.processes, pid)
			}
		}
		pt.mu.Unlock()
	}
}
