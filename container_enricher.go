package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ContainerInfo holds container and pod metadata for a process.
type ContainerInfo struct {
	ContainerID   string
	ContainerName string
	ImageName     string
	ImageDigest   string
	PodNamespace  string
	PodName       string
	PodUID        string
	Labels        map[string]string
	LastSeen      time.Time
}

// ContainerEnricher maps PIDs to container/pod metadata by reading cgroup
// information from /proc. It maintains an in-memory cache that is periodically
// refreshed and cleaned.
type ContainerEnricher struct {
	mu             sync.RWMutex
	pidToContainer map[uint32]*ContainerInfo
	containerByID  map[string]*ContainerInfo
	procRoot       string
	logger         *log.Logger
}

// NewContainerEnricher creates a ContainerEnricher and starts background
// goroutines for periodic refresh and stale-entry cleanup.
func NewContainerEnricher(procRoot string, logger *log.Logger) *ContainerEnricher {
	if procRoot == "" {
		procRoot = "/proc"
		if envRoot := os.Getenv("HOST_PROC"); envRoot != "" {
			procRoot = envRoot
		}
	}

	ce := &ContainerEnricher{
		pidToContainer: make(map[uint32]*ContainerInfo),
		containerByID:  make(map[string]*ContainerInfo),
		procRoot:       procRoot,
		logger:         logger,
	}

	// Initial scan
	ce.RefreshFromProc()

	// Background refresh every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ce.RefreshFromProc()
		}
	}()

	// Background cleanup every 2 minutes
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			ce.cleanup()
		}
	}()

	return ce
}

// EnrichByPID looks up container info for a given PID. It first checks the
// cache, then falls back to reading /proc/<pid>/cgroup to extract the
// container ID and pod UID.
func (ce *ContainerEnricher) EnrichByPID(pid uint32) *ContainerInfo {
	// Check cache first
	ce.mu.RLock()
	if info, ok := ce.pidToContainer[pid]; ok {
		ce.mu.RUnlock()
		return info
	}
	ce.mu.RUnlock()

	// Read cgroup info from proc
	info := ce.resolveFromCgroup(pid)
	if info == nil {
		return nil
	}

	// Cache the result
	ce.mu.Lock()
	ce.pidToContainer[pid] = info
	if info.ContainerID != "" {
		ce.containerByID[info.ContainerID] = info
	}
	ce.mu.Unlock()

	return info
}

// EnrichByContainerID looks up container info by container ID.
func (ce *ContainerEnricher) EnrichByContainerID(containerID string) *ContainerInfo {
	ce.mu.RLock()
	defer ce.mu.RUnlock()

	if info, ok := ce.containerByID[containerID]; ok {
		return info
	}
	return nil
}

// RefreshFromProc scans /proc for all PIDs and builds the PID-to-container
// mapping by reading each process's cgroup file.
func (ce *ContainerEnricher) RefreshFromProc() {
	entries, err := os.ReadDir(ce.procRoot)
	if err != nil {
		ce.logger.Printf("container-enricher: failed to read %s: %v", ce.procRoot, err)
		return
	}

	newPIDMap := make(map[uint32]*ContainerInfo)
	newContainerMap := make(map[string]*ContainerInfo)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '1' || name[0] > '9' {
			continue
		}

		// Parse PID from directory name
		var pid uint32
		valid := true
		for _, ch := range name {
			if ch < '0' || ch > '9' {
				valid = false
				break
			}
			pid = pid*10 + uint32(ch-'0')
		}
		if !valid || pid == 0 {
			continue
		}

		info := ce.resolveFromCgroup(pid)
		if info == nil {
			continue
		}

		newPIDMap[pid] = info
		if info.ContainerID != "" {
			newContainerMap[info.ContainerID] = info
		}
	}

	ce.mu.Lock()
	ce.pidToContainer = newPIDMap
	ce.containerByID = newContainerMap
	ce.mu.Unlock()
}

// cleanup removes stale entries that have not been seen for more than 10
// minutes.
func (ce *ContainerEnricher) cleanup() {
	cutoff := time.Now().Add(-10 * time.Minute)

	ce.mu.Lock()
	defer ce.mu.Unlock()

	for pid, info := range ce.pidToContainer {
		if info.LastSeen.Before(cutoff) {
			delete(ce.pidToContainer, pid)
		}
	}

	for id, info := range ce.containerByID {
		if info.LastSeen.Before(cutoff) {
			delete(ce.containerByID, id)
		}
	}
}

// resolveFromCgroup reads /proc/<pid>/cgroup and extracts container ID and
// pod UID from the cgroup path.
func (ce *ContainerEnricher) resolveFromCgroup(pid uint32) *ContainerInfo {
	cgroupPath := filepath.Join(ce.procRoot, fmt.Sprintf("%d", pid), "cgroup")
	f, err := os.Open(cgroupPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var containerID string
	var cgroupContent strings.Builder

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		cgroupContent.WriteString(line)
		cgroupContent.WriteString("\n")

		if containerID == "" {
			containerID = extractContainerIDFromCgroupLine(line)
		}
	}

	if containerID == "" {
		return nil
	}

	// Use existing function from mesh_forwarder.go to extract pod UID
	podUID := extractPodUIDFromCgroup(cgroupContent.String())

	return &ContainerInfo{
		ContainerID: containerID,
		PodUID:      podUID,
		Labels:      make(map[string]string),
		LastSeen:    time.Now(),
	}
}

// extractContainerIDFromCgroupLine extracts the container ID from a single
// cgroup line. It handles the common container runtime prefixes:
//   - docker-<id>.scope
//   - cri-containerd-<id>.scope
//   - crio-<id>.scope
//   - plain <64-hex-char> segment (Docker without systemd)
func extractContainerIDFromCgroupLine(line string) string {
	// Look for known runtime prefixes in the cgroup path
	prefixes := []string{"docker-", "cri-containerd-", "crio-"}
	for _, prefix := range prefixes {
		idx := strings.LastIndex(line, prefix)
		if idx == -1 {
			continue
		}
		rest := line[idx+len(prefix):]
		// Strip ".scope" suffix if present
		rest = strings.TrimSuffix(rest, ".scope")
		// The container ID is everything up to the next path separator
		if slashIdx := strings.IndexByte(rest, '/'); slashIdx != -1 {
			rest = rest[:slashIdx]
		}
		if len(rest) >= 12 && isHexString(rest) {
			return rest
		}
	}

	// Fallback: look for a 64-character hex segment as the last path component
	// This handles Docker without systemd: .../docker/<containerID>
	parts := strings.Split(line, "/")
	for i := len(parts) - 1; i >= 0; i-- {
		seg := parts[i]
		if len(seg) == 64 && isHexString(seg) {
			return seg
		}
	}

	return ""
}

// isHexString returns true if s consists entirely of hexadecimal characters.
func isHexString(s string) bool {
	for _, ch := range s {
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')) {
			return false
		}
	}
	return len(s) > 0
}
