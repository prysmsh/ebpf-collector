package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyTLSLib(t *testing.T) {
	tests := []struct {
		name     string
		expected string
	}{
		{"libssl.so.3", "openssl"},
		{"libssl.so.1.1", "openssl"},
		{"libgnutls.so.30", "gnutls"},
		{"libgnutls.so", "gnutls"},
		{"libcrypto.so.3", "openssl"}, // still works for classifyTLSLib even though scanner excludes libcrypto
	}

	for _, tc := range tests {
		got := classifyTLSLib(tc.name)
		if got != tc.expected {
			t.Errorf("classifyTLSLib(%q) = %q, want %q", tc.name, got, tc.expected)
		}
	}
}

func TestPathSetsEqual(t *testing.T) {
	a := map[string]struct{}{"/a": {}, "/b": {}}
	b := map[string]struct{}{"/a": {}, "/b": {}}
	c := map[string]struct{}{"/a": {}, "/c": {}}
	d := map[string]struct{}{"/a": {}}

	if !pathSetsEqual(a, b) {
		t.Error("expected a == b")
	}
	if pathSetsEqual(a, c) {
		t.Error("expected a != c")
	}
	if pathSetsEqual(a, d) {
		t.Error("expected a != d (different length)")
	}
}

func TestScanPIDMaps_MockProc(t *testing.T) {
	// Create a mock /proc/<pid>/maps structure.
	tmpDir := t.TempDir()

	pid := uint32(12345)
	pidDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a mock libssl.so.3 in the "container root"
	containerRoot := filepath.Join(pidDir, "root", "usr", "lib", "x86_64-linux-gnu")
	if err := os.MkdirAll(containerRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	libPath := filepath.Join(containerRoot, "libssl.so.3")
	if err := os.WriteFile(libPath, []byte("fake-library"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a mock maps file
	mapsContent := `7f0000000000-7f0000010000 r-xp 00000000 08:01 12345 /usr/lib/x86_64-linux-gnu/libssl.so.3
7f0000020000-7f0000030000 rw-p 00010000 08:01 12345 [heap]
`
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), []byte(mapsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "[test] ", 0)
	scanner := NewTLSLibraryScanner(tmpDir, nil, logger)
	libs := scanner.scanPIDMaps(pid)

	if len(libs) != 1 {
		t.Fatalf("expected 1 library, got %d", len(libs))
	}
	if libs[0].Type != "openssl" {
		t.Errorf("expected type 'openssl', got %q", libs[0].Type)
	}
	if libs[0].Path != libPath {
		t.Errorf("expected path %q, got %q", libPath, libs[0].Path)
	}
}

func TestScanPIDMaps_GnuTLS(t *testing.T) {
	tmpDir := t.TempDir()
	pid := uint32(999)
	pidDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	containerRoot := filepath.Join(pidDir, "root", "usr", "lib")
	if err := os.MkdirAll(containerRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	libPath := filepath.Join(containerRoot, "libgnutls.so.30")
	if err := os.WriteFile(libPath, []byte("fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	mapsContent := `7f0000000000-7f0000010000 r-xp 00000000 08:01 99999 /usr/lib/libgnutls.so.30
`
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), []byte(mapsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "[test] ", 0)
	scanner := NewTLSLibraryScanner(tmpDir, nil, logger)
	libs := scanner.scanPIDMaps(pid)

	if len(libs) != 1 {
		t.Fatalf("expected 1 library, got %d", len(libs))
	}
	if libs[0].Type != "gnutls" {
		t.Errorf("expected type 'gnutls', got %q", libs[0].Type)
	}
}

func TestScanPIDMaps_SkipDeleted(t *testing.T) {
	tmpDir := t.TempDir()
	pid := uint32(111)
	pidDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}

	mapsContent := `7f0000000000-7f0000010000 r-xp 00000000 08:01 12345 /usr/lib/libssl.so.3 (deleted)
`
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), []byte(mapsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "[test] ", 0)
	scanner := NewTLSLibraryScanner(tmpDir, nil, logger)
	libs := scanner.scanPIDMaps(pid)

	if len(libs) != 0 {
		t.Errorf("expected 0 libraries for deleted mapping, got %d", len(libs))
	}
}

func TestSkipComms(t *testing.T) {
	tmpDir := t.TempDir()
	pid := uint32(222)
	pidDir := filepath.Join(tmpDir, fmt.Sprintf("%d", pid))
	containerRoot := filepath.Join(pidDir, "root", "usr", "lib")
	if err := os.MkdirAll(containerRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(containerRoot, "libssl.so.3"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mapsContent := `7f0000000000-7f0000010000 r-xp 00000000 08:01 12345 /usr/lib/libssl.so.3
`
	if err := os.WriteFile(filepath.Join(pidDir, "maps"), []byte(mapsContent), 0o644); err != nil {
		t.Fatal(err)
	}
	// Write comm file
	if err := os.WriteFile(filepath.Join(pidDir, "comm"), []byte("envoy\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "[test] ", 0)
	scanner := NewTLSLibraryScanner(tmpDir, []string{"envoy"}, logger)
	libs := scanner.Scan()

	if len(libs) != 0 {
		t.Errorf("expected 0 libraries (envoy should be skipped), got %d", len(libs))
	}
}
