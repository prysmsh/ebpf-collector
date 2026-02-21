package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// TLSUprobeManager manages dynamic uprobe attachment and detachment for
// discovered TLS libraries. It loads the tls_monitor.o eBPF object and
// attaches uprobes to SSL_write, SSL_read, etc. for each unique library.
type TLSUprobeManager struct {
	collection *ebpf.Collection
	links      map[string][]link.Link // library path → attached links
	mu         sync.Mutex
	logger     *log.Logger
}

// tlsProgramNames maps eBPF program section names to TLS function names and
// the library types they apply to.
type tlsProbeSpec struct {
	progName string // eBPF program name in the collection
	symbol   string // userspace symbol to attach to
	libTypes []string
	isRet    bool // true for uretprobe
}

var opensslProbes = []tlsProbeSpec{
	{progName: "trace_ssl_write_entry", symbol: "SSL_write", libTypes: []string{"openssl", "boringssl"}},
	{progName: "trace_ssl_read_entry", symbol: "SSL_read", libTypes: []string{"openssl", "boringssl"}},
	{progName: "trace_ssl_read_return", symbol: "SSL_read", libTypes: []string{"openssl", "boringssl"}, isRet: true},
}

var gnutlsProbes = []tlsProbeSpec{
	{progName: "trace_gnutls_send_entry", symbol: "gnutls_record_send", libTypes: []string{"gnutls"}},
	{progName: "trace_gnutls_recv_entry", symbol: "gnutls_record_recv", libTypes: []string{"gnutls"}},
	{progName: "trace_gnutls_recv_return", symbol: "gnutls_record_recv", libTypes: []string{"gnutls"}, isRet: true},
}

// NewTLSUprobeManager creates a manager that loads the eBPF TLS monitor
// object file and prepares for dynamic uprobe attachment. Returns nil if
// the object file does not exist (TLS monitoring not compiled).
func NewTLSUprobeManager(ebpfDir string, logger *log.Logger) (*TLSUprobeManager, error) {
	objectPath := filepath.Join(ebpfDir, "tls_monitor.o")
	if _, err := os.Stat(objectPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("tls_monitor.o not found at %s", objectPath)
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load tls_monitor.o: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS eBPF collection: %w", err)
	}

	return &TLSUprobeManager{
		collection: coll,
		links:      make(map[string][]link.Link),
		logger:     logger,
	}, nil
}

// Collection returns the loaded eBPF collection for ring buffer access.
func (m *TLSUprobeManager) Collection() *ebpf.Collection {
	return m.collection
}

// AttachLibrary attaches uprobes to a discovered TLS library. It skips
// libraries that are already attached.
func (m *TLSUprobeManager) AttachLibrary(lib *TLSLibrary) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, attached := m.links[lib.Path]; attached {
		return nil // already attached
	}

	ex, err := link.OpenExecutable(lib.Path)
	if err != nil {
		return fmt.Errorf("failed to open executable %s: %w", lib.Path, err)
	}

	var probes []tlsProbeSpec
	switch lib.Type {
	case "openssl", "boringssl":
		probes = opensslProbes
	case "gnutls":
		probes = gnutlsProbes
	default:
		probes = opensslProbes // default to OpenSSL symbols
	}

	var attached []link.Link
	for _, spec := range probes {
		prog := m.collection.Programs[spec.progName]
		if prog == nil {
			m.logger.Printf("tls-uprobe: program %q not found in collection", spec.progName)
			continue
		}

		var l link.Link
		if spec.isRet {
			l, err = ex.Uretprobe(spec.symbol, prog, nil)
		} else {
			l, err = ex.Uprobe(spec.symbol, prog, nil)
		}
		if err != nil {
			m.logger.Printf("tls-uprobe: failed to attach %s to %s in %s: %v",
				spec.progName, spec.symbol, lib.Path, err)
			continue
		}
		attached = append(attached, l)
		kind := "uprobe"
		if spec.isRet {
			kind = "uretprobe"
		}
		m.logger.Printf("tls-uprobe: attached %s/%s to %s (%s)", kind, spec.symbol, lib.Path, lib.Type)
	}

	if len(attached) == 0 {
		return fmt.Errorf("no probes could be attached to %s", lib.Path)
	}

	m.links[lib.Path] = attached
	return nil
}

// DetachLibrary detaches all uprobes for a given library path.
func (m *TLSUprobeManager) DetachLibrary(path string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	links, ok := m.links[path]
	if !ok {
		return
	}

	for _, l := range links {
		if err := l.Close(); err != nil {
			m.logger.Printf("tls-uprobe: error closing link for %s: %v", path, err)
		}
	}
	delete(m.links, path)
	m.logger.Printf("tls-uprobe: detached all probes from %s", path)
}

// Reconcile synchronizes attached libraries with the current set of
// discovered libraries. Attaches probes to new libraries and detaches
// from libraries no longer in use.
func (m *TLSUprobeManager) Reconcile(libs []*TLSLibrary) {
	currentPaths := make(map[string]struct{}, len(libs))
	for _, lib := range libs {
		currentPaths[lib.Path] = struct{}{}
	}

	// Detach from libraries no longer present.
	m.mu.Lock()
	var toDetach []string
	for path := range m.links {
		if _, ok := currentPaths[path]; !ok {
			toDetach = append(toDetach, path)
		}
	}
	m.mu.Unlock()

	for _, path := range toDetach {
		m.DetachLibrary(path)
	}

	// Attach to new libraries.
	for _, lib := range libs {
		if err := m.AttachLibrary(lib); err != nil {
			m.logger.Printf("tls-uprobe: failed to attach to %s: %v", lib.Path, err)
		}
	}
}

// AttachedCount returns the number of currently attached library paths.
func (m *TLSUprobeManager) AttachedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.links)
}

// Close detaches all uprobes and closes the eBPF collection.
func (m *TLSUprobeManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for path, links := range m.links {
		for _, l := range links {
			l.Close()
		}
		delete(m.links, path)
		m.logger.Printf("tls-uprobe: closed probes for %s", path)
	}

	if m.collection != nil {
		m.collection.Close()
	}
}
