package output

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAlert() Alert {
	return Alert{
		Timestamp: time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC),
		RuleName:  "Test Rule",
		Output:    "Shell bash detected (pid=1234)",
		Priority:  "CRITICAL",
		Tags:      []string{"test", "shell"},
		Source:    "ebpf",
	}
}

func TestStdoutWriter(t *testing.T) {
	// Redirect stdout to capture output.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	writer := NewStdoutWriter()
	if err := writer.WriteAlert(testAlert()); err != nil {
		t.Fatalf("WriteAlert: %v", err)
	}
	writer.Close()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	buf.ReadFrom(r)

	var alert Alert
	if err := json.Unmarshal(buf.Bytes(), &alert); err != nil {
		t.Fatalf("unmarshal output: %v (output: %s)", err, buf.String())
	}
	if alert.RuleName != "Test Rule" {
		t.Errorf("expected rule name 'Test Rule', got %q", alert.RuleName)
	}
}

func TestFileWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")

	writer, err := NewFileWriter(path, 0, 0)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}

	for i := 0; i < 5; i++ {
		if err := writer.WriteAlert(testAlert()); err != nil {
			t.Fatalf("WriteAlert: %v", err)
		}
	}
	writer.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Errorf("expected 5 lines, got %d", len(lines))
	}
}

func TestFileWriterRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.jsonl")

	// Small maxBytes to trigger rotation quickly.
	writer, err := NewFileWriter(path, 200, 3)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}

	for i := 0; i < 10; i++ {
		if err := writer.WriteAlert(testAlert()); err != nil {
			t.Fatalf("WriteAlert: %v", err)
		}
	}
	writer.Close()

	// Check that rotated files exist.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("main file should exist: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("rotated file .1 should exist: %v", err)
	}
}

func TestSyslogWriter(t *testing.T) {
	var buf bytes.Buffer
	writer := NewSyslogWriter(&buf, "prysm-ebpf")

	if err := writer.WriteAlert(testAlert()); err != nil {
		t.Fatalf("WriteAlert: %v", err)
	}
	writer.Close()

	output := buf.String()
	if !strings.Contains(output, "Test Rule") {
		t.Errorf("syslog output should contain rule name: %s", output)
	}
	if !strings.Contains(output, "<10>") {
		t.Errorf("syslog output should have priority 10 (user.crit): %s", output)
	}
}

func TestMultiWriter(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	w1 := NewSyslogWriter(&buf1, "w1")
	w2 := NewSyslogWriter(&buf2, "w2")

	logger := log.New(os.Stderr, "[test] ", 0)
	multi := NewMultiWriter(logger, w1, w2)

	if err := multi.WriteAlert(testAlert()); err != nil {
		t.Fatalf("WriteAlert: %v", err)
	}
	multi.Close()

	if !strings.Contains(buf1.String(), "Test Rule") {
		t.Error("w1 should have received the alert")
	}
	if !strings.Contains(buf2.String(), "Test Rule") {
		t.Error("w2 should have received the alert")
	}
}
