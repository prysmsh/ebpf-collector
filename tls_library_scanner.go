package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// TLSLibrary represents a TLS library discovered on the host.
type TLSLibrary struct {
	Path string // host-accessible path (e.g. /proc/<PID>/root/usr/lib/libssl.so.3)
	Type string // "openssl", "gnutls", "boringssl"
	PIDs []uint32
}

// TLSLibraryScanner discovers TLS libraries loaded by processes on the host
// by scanning /proc/*/maps.
type TLSLibraryScanner struct {
	procRoot string // e.g. "/proc" or "/host/proc"
	known    map[string]*TLSLibrary
	mu       sync.RWMutex
	logger   *log.Logger
	// skipComms is a set of process comm names to ignore.
	skipComms map[string]struct{}
}

// tlsLibPattern matches common TLS shared library names in /proc/PID/maps.
// Note: libcrypto.so is excluded because SSL_read/SSL_write are only in
// libssl.so; attaching uprobes to libcrypto produces "symbol not found" noise.
var tlsLibPattern = regexp.MustCompile(`(libssl\.so[.\d]*|libgnutls\.so[.\d]*)`)

// NewTLSLibraryScanner creates a scanner that reads from the given proc root.
func NewTLSLibraryScanner(procRoot string, skipComms []string, logger *log.Logger) *TLSLibraryScanner {
	sc := make(map[string]struct{}, len(skipComms))
	for _, c := range skipComms {
		sc[c] = struct{}{}
	}
	return &TLSLibraryScanner{
		procRoot:  procRoot,
		known:     make(map[string]*TLSLibrary),
		logger:    logger,
		skipComms: sc,
	}
}

// Scan performs a single scan of /proc/*/maps and returns all discovered
// TLS libraries. It deduplicates by resolved host path and skips Go binaries.
func (s *TLSLibraryScanner) Scan() []*TLSLibrary {
	entries, err := os.ReadDir(s.procRoot)
	if err != nil {
		s.logger.Printf("tls-scanner: failed to read %s: %v", s.procRoot, err)
		return nil
	}

	// Temporary map: library host path → set of PIDs
	found := make(map[string]*TLSLibrary)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue // not a PID directory
		}

		// Check skip list via /proc/PID/comm
		if len(s.skipComms) > 0 {
			comm := s.readComm(uint32(pid))
			if _, skip := s.skipComms[comm]; skip {
				continue
			}
		}

		// Skip Go binaries: they use crypto/tls (no OpenSSL) and uretprobes
		// crash Go processes because Go doesn't save callee-saved registers.
		if s.isGoBinary(uint32(pid)) {
			continue
		}

		libs := s.scanPIDMaps(uint32(pid))
		for _, lib := range libs {
			existing, ok := found[lib.Path]
			if ok {
				existing.PIDs = append(existing.PIDs, uint32(pid))
			} else {
				lib.PIDs = []uint32{uint32(pid)}
				found[lib.Path] = lib
			}
		}
	}

	s.mu.Lock()
	s.known = found
	s.mu.Unlock()

	result := make([]*TLSLibrary, 0, len(found))
	for _, lib := range found {
		result = append(result, lib)
	}
	return result
}

// Known returns the currently known TLS libraries from the last scan.
func (s *TLSLibraryScanner) Known() []*TLSLibrary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*TLSLibrary, 0, len(s.known))
	for _, lib := range s.known {
		result = append(result, lib)
	}
	return result
}

// RunPeriodicScan runs Scan() every interval until the stop channel is closed.
func (s *TLSLibraryScanner) RunPeriodicScan(interval time.Duration, stop <-chan struct{}, onChange func([]*TLSLibrary)) {
	// Initial scan.
	libs := s.Scan()
	if onChange != nil && len(libs) > 0 {
		onChange(libs)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			oldPaths := s.knownPaths()
			libs := s.Scan()
			newPaths := s.knownPaths()

			// Detect changes: new or removed libraries.
			if !pathSetsEqual(oldPaths, newPaths) && onChange != nil {
				onChange(libs)
			}
		}
	}
}

func (s *TLSLibraryScanner) knownPaths() map[string]struct{} {
	s.mu.RLock()
	defer s.mu.RUnlock()
	paths := make(map[string]struct{}, len(s.known))
	for p := range s.known {
		paths[p] = struct{}{}
	}
	return paths
}

func pathSetsEqual(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// scanPIDMaps reads /proc/<pid>/maps and returns TLS libraries found.
func (s *TLSLibraryScanner) scanPIDMaps(pid uint32) []*TLSLibrary {
	mapsPath := filepath.Join(s.procRoot, fmt.Sprintf("%d", pid), "maps")
	f, err := os.Open(mapsPath)
	if err != nil {
		return nil // process may have exited
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var libs []*TLSLibrary

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// Only look at executable mappings (r-xp)
		if !strings.Contains(line, "r-xp") && !strings.Contains(line, "r--p") {
			continue
		}

		matches := tlsLibPattern.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		libName := matches[1]
		// Extract the mapped file path (last field in the line).
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mappedPath := fields[len(fields)-1]
		if mappedPath == "" || mappedPath == "(deleted)" {
			continue
		}

		// Convert container-internal path to host-accessible path via /proc/PID/root/...
		hostPath := filepath.Join(s.procRoot, fmt.Sprintf("%d", pid), "root", mappedPath)

		// Deduplicate within this PID.
		if _, ok := seen[hostPath]; ok {
			continue
		}
		seen[hostPath] = struct{}{}

		// Verify the file exists and is readable.
		if _, err := os.Stat(hostPath); err != nil {
			continue
		}

		lib := &TLSLibrary{
			Path: hostPath,
			Type: classifyTLSLib(libName),
		}
		libs = append(libs, lib)
	}

	return libs
}

// classifyTLSLib determines the TLS library type from the filename.
func classifyTLSLib(name string) string {
	switch {
	case strings.HasPrefix(name, "libgnutls"):
		return "gnutls"
	case strings.HasPrefix(name, "libssl"):
		return "openssl"
	default:
		return "openssl"
	}
}

// isGoBinary checks if the process's executable is a Go binary by looking
// for the .go.buildinfo ELF section.
func (s *TLSLibraryScanner) isGoBinary(pid uint32) bool {
	exePath := filepath.Join(s.procRoot, fmt.Sprintf("%d", pid), "exe")

	f, err := elf.Open(exePath)
	if err != nil {
		return false // not an ELF or not readable — assume not Go
	}
	defer f.Close()

	// Go binaries have a .go.buildinfo section.
	if f.Section(".go.buildinfo") != nil {
		return true
	}

	// Fallback: look for runtime.main symbol (less reliable but catches
	// stripped binaries).
	syms, err := f.Symbols()
	if err == nil {
		for _, sym := range syms {
			if sym.Name == "runtime.main" {
				return true
			}
		}
	}

	return false
}

// readComm reads the comm name for a PID from /proc/PID/comm.
func (s *TLSLibraryScanner) readComm(pid uint32) string {
	data, err := os.ReadFile(filepath.Join(s.procRoot, fmt.Sprintf("%d", pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
