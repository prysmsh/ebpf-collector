// Package output defines the OutputWriter interface and standard
// implementations for delivering security alerts to various sinks.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Alert is the data structure written to output sinks. It mirrors
// rules.Alert but lives in this package to avoid circular imports.
type Alert struct {
	Timestamp   time.Time         `json:"timestamp"`
	RuleName    string            `json:"rule"`
	Output      string            `json:"output"`
	Priority    string            `json:"priority"`
	Tags        []string          `json:"tags,omitempty"`
	Source      string            `json:"source"`
	Fields      map[string]string `json:"fields,omitempty"`
	ProcessInfo map[string]any    `json:"process,omitempty"`
	NetworkInfo map[string]any    `json:"network,omitempty"`
	FileInfo    map[string]any    `json:"file,omitempty"`
}

// Writer is the interface that output sinks must implement.
type Writer interface {
	// WriteAlert delivers a single alert to the sink. Implementations
	// must be safe for concurrent use.
	WriteAlert(alert Alert) error

	// Close releases any resources held by the writer.
	Close() error
}

// ---- JSON stdout writer ----

// StdoutWriter writes JSON-encoded alerts to stdout.
type StdoutWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// NewStdoutWriter creates a writer that outputs JSON alerts to stdout.
func NewStdoutWriter() *StdoutWriter {
	return &StdoutWriter{
		enc: json.NewEncoder(os.Stdout),
	}
}

func (w *StdoutWriter) WriteAlert(alert Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(alert)
}

func (w *StdoutWriter) Close() error { return nil }

// ---- File writer with rotation ----

// FileWriter writes JSON alerts to a file with optional size-based rotation.
type FileWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File
	size     int64
}

// NewFileWriter creates a writer that appends JSON alerts to the given file.
// maxBytes controls file rotation size (0 = no rotation). maxFiles controls
// how many rotated files to keep.
func NewFileWriter(path string, maxBytes int64, maxFiles int) (*FileWriter, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create dir %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	info, _ := f.Stat()
	var currentSize int64
	if info != nil {
		currentSize = info.Size()
	}

	return &FileWriter{
		path:     path,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
		file:     f,
		size:     currentSize,
	}, nil
}

func (w *FileWriter) WriteAlert(alert Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	w.mu.Lock()
	defer w.mu.Unlock()

	if w.maxBytes > 0 && w.size+int64(len(data)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
	}

	n, err := w.file.Write(data)
	w.size += int64(n)
	return err
}

func (w *FileWriter) rotate() error {
	w.file.Close()

	// Shift existing rotated files.
	for i := w.maxFiles - 1; i > 0; i-- {
		src := fmt.Sprintf("%s.%d", w.path, i)
		dst := fmt.Sprintf("%s.%d", w.path, i+1)
		os.Rename(src, dst)
	}

	os.Rename(w.path, w.path+".1")

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// ---- Syslog writer ----

// SyslogWriter writes alerts to a syslog-style destination (local file or
// network). For simplicity it writes RFC 5424-like lines to an io.Writer.
type SyslogWriter struct {
	mu     sync.Mutex
	writer io.Writer
	tag    string
}

// NewSyslogWriter creates a syslog writer that writes to the given io.Writer
// (e.g. a UDP/TCP connection or os.Stderr).
func NewSyslogWriter(w io.Writer, tag string) *SyslogWriter {
	return &SyslogWriter{writer: w, tag: tag}
}

func (w *SyslogWriter) WriteAlert(alert Alert) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// RFC 5424 simplified: <priority>1 timestamp tag - - - msg
	pri := priorityToSyslog(alert.Priority)
	ts := alert.Timestamp.UTC().Format(time.RFC3339)
	msg := fmt.Sprintf("<%d>1 %s %s - - - rule=%q %s\n",
		pri, ts, w.tag, alert.RuleName, alert.Output)
	_, err := io.WriteString(w.writer, msg)
	return err
}

func (w *SyslogWriter) Close() error {
	if closer, ok := w.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func priorityToSyslog(priority string) int {
	// Facility 1 (user-level) + severity
	const facility = 1 << 3
	switch priority {
	case "EMERGENCY":
		return facility | 0
	case "ALERT":
		return facility | 1
	case "CRITICAL":
		return facility | 2
	case "ERROR":
		return facility | 3
	case "WARNING", "WARN":
		return facility | 4
	case "NOTICE":
		return facility | 5
	case "INFORMATIONAL", "INFO":
		return facility | 6
	case "DEBUG":
		return facility | 7
	default:
		return facility | 4 // default warning
	}
}

// ---- Multi-writer ----

// MultiWriter fans out alerts to multiple writers.
type MultiWriter struct {
	writers []Writer
	logger  *log.Logger
}

// NewMultiWriter creates a writer that sends each alert to all sub-writers.
func NewMultiWriter(logger *log.Logger, writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers, logger: logger}
}

func (m *MultiWriter) WriteAlert(alert Alert) error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.WriteAlert(alert); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			m.logger.Printf("output writer error: %v", err)
		}
	}
	return firstErr
}

func (m *MultiWriter) Close() error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
