package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// SecurityManager handles all security-related operations for the eBPF collector
type SecurityManager struct {
	rateLimiter    *RateLimiter
	eventValidator *EventValidator
	auditLogger    *AuditLogger
	mu             sync.RWMutex
}

// RateLimiter implements token bucket rate limiting for events
type RateLimiter struct {
	tokens     int
	capacity   int
	refillRate int // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// EventValidator validates and sanitizes incoming eBPF events
type EventValidator struct {
	maxStringLen   int
	allowedChars   *regexp.Regexp
	bannedPatterns []*regexp.Regexp
}

// AuditLogger logs security-relevant events for monitoring
type AuditLogger struct {
	file   *os.File
	logger *log.Logger
	mu     sync.Mutex
}

// NewSecurityManager creates a new security manager with configurable rate limits
func NewSecurityManager() (*SecurityManager, error) {
	// Get rate limit configuration from environment variables
	capacity := getEnvAsInt("EBPF_RATE_LIMIT_CAPACITY", 10000)
	refillRate := getEnvAsInt("EBPF_RATE_LIMIT_REFILL_RATE", 1000)
	
	rateLimiter := &RateLimiter{
		tokens:     capacity,
		capacity:   capacity,
		refillRate: refillRate, // tokens per second
		lastRefill: time.Now(),
	}

	log.Printf("Rate limiter initialized: capacity=%d, refillRate=%d tokens/sec", capacity, refillRate)

	eventValidator := &EventValidator{
		maxStringLen: 512,
		allowedChars: regexp.MustCompile(`^[a-zA-Z0-9\-_./\s\[\](){}:=,]*$`),
		bannedPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(password|token|secret|key|auth)`),
			regexp.MustCompile(`\.\./`),           // Path traversal
			regexp.MustCompile(`[\x00-\x1F\x7F]`), // Control characters
		},
	}

	// Try to create file-based audit logger, fall back to stdout
	auditLogPath := os.Getenv("EBPF_AUDIT_LOG_PATH")
	if auditLogPath == "" {
		auditLogPath = "/var/log/ebpf-security.log"
	}
	
	auditLogger, err := NewAuditLogger(auditLogPath)
	if err != nil {
		// Fall back to stdout-based audit logging
		log.Printf("Warning: cannot create file-based audit logger (%v), using stdout", err)
		auditLogger = NewStdoutAuditLogger()
	}

	return &SecurityManager{
		rateLimiter:    rateLimiter,
		eventValidator: eventValidator,
		auditLogger:    auditLogger,
	}, nil
}

// ValidateAndSanitizeEvent validates and sanitizes an eBPF security event
func (sm *SecurityManager) ValidateAndSanitizeEvent(event *SecurityEvent) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Rate limiting check
	if !sm.rateLimiter.Allow() {
		sm.auditLogger.LogSecurityEvent("RATE_LIMIT_EXCEEDED", map[string]interface{}{
			"pid": event.PID,
			"uid": event.UID,
		})
		return fmt.Errorf("rate limit exceeded")
	}

	// Validate basic event structure
	if event.PID == 0 || event.Timestamp == 0 {
		return fmt.Errorf("invalid event: missing required fields")
	}

	// Validate and sanitize comm field
	comm := nullTerminatedString(event.Comm[:])
	if err := sm.eventValidator.ValidateString(comm, "comm"); err != nil {
		return fmt.Errorf("invalid comm field: %w", err)
	}

	// Validate container ID if present
	containerID := nullTerminatedString(event.ContainerID[:])
	if containerID != "" {
		if err := sm.eventValidator.ValidateContainerID(containerID); err != nil {
			return fmt.Errorf("invalid container ID: %w", err)
		}
	}

	// Security level validation
	if event.SecurityLevel > SecurityLevelCritical {
		sm.auditLogger.LogSecurityEvent("INVALID_SECURITY_LEVEL", map[string]interface{}{
			"level": event.SecurityLevel,
			"pid":   event.PID,
		})
		return fmt.Errorf("invalid security level: %d", event.SecurityLevel)
	}

	// Log high-severity events
	if event.SecurityLevel >= SecurityLevelHigh {
		sm.auditLogger.LogSecurityEvent("HIGH_SEVERITY_EVENT", map[string]interface{}{
			"event_type": event.EventType,
			"pid":        event.PID,
			"uid":        event.UID,
			"comm":       comm,
		})
	}

	return nil
}

// Allow checks if an event should be allowed based on rate limiting
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(rl.lastRefill)

	// Refill tokens based on elapsed time
	tokensToAdd := int(elapsed.Seconds()) * rl.refillRate
	if tokensToAdd > 0 {
		rl.tokens = min(rl.capacity, rl.tokens+tokensToAdd)
		rl.lastRefill = now
	}

	if rl.tokens > 0 {
		rl.tokens--
		return true
	}
	return false
}

// ValidateString validates and sanitizes a string field
func (ev *EventValidator) ValidateString(s, fieldName string) error {
	if len(s) > ev.maxStringLen {
		return fmt.Errorf("field %s too long: %d > %d", fieldName, len(s), ev.maxStringLen)
	}

	if !ev.allowedChars.MatchString(s) {
		return fmt.Errorf("field %s contains invalid characters", fieldName)
	}

	for _, pattern := range ev.bannedPatterns {
		if pattern.MatchString(s) {
			return fmt.Errorf("field %s contains banned pattern", fieldName)
		}
	}

	return nil
}

// ValidateContainerID validates a container ID format
func (ev *EventValidator) ValidateContainerID(containerID string) error {
	// Container IDs should be hex strings of specific lengths
	if len(containerID) != 64 && len(containerID) != 12 {
		return fmt.Errorf("invalid container ID length: %d", len(containerID))
	}

	if _, err := hex.DecodeString(containerID); err != nil {
		return fmt.Errorf("container ID is not valid hex: %w", err)
	}

	return nil
}

// NewAuditLogger creates a new audit logger writing to a file
func NewAuditLogger(filepath string) (*AuditLogger, error) {
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	logger := log.New(file, "", log.LstdFlags|log.Lmicroseconds)

	return &AuditLogger{
		file:   file,
		logger: logger,
	}, nil
}

// NewStdoutAuditLogger creates an audit logger that writes to stdout
func NewStdoutAuditLogger() *AuditLogger {
	return &AuditLogger{
		file:   nil, // No file to close
		logger: log.New(os.Stdout, "[AUDIT] ", log.LstdFlags|log.Lmicroseconds),
	}
}

// LogSecurityEvent logs a security event to the audit log
func (al *AuditLogger) LogSecurityEvent(eventType string, data map[string]interface{}) {
	al.mu.Lock()
	defer al.mu.Unlock()

	entry := map[string]interface{}{
		"timestamp":  time.Now().UTC(),
		"event_type": eventType,
		"pid":        os.Getpid(),
		"data":       data,
	}

	// Convert to JSON for structured logging
	if jsonData, err := json.Marshal(entry); err == nil {
		al.logger.Printf("AUDIT: %s", string(jsonData))
	} else {
		al.logger.Printf("AUDIT: %s %+v", eventType, data)
	}
}

// Close closes the audit logger
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	if al.file != nil {
		return al.file.Close()
	}
	return nil
}

// VerifyCapabilities checks that the process has required capabilities
func VerifyCapabilities() error {
	// Allow skipping capability verification for development/containerized environments
	if skipCaps := strings.TrimSpace(os.Getenv("PRYSM_SKIP_CAPABILITY_CHECK")); skipCaps == "true" {
		log.Printf("Capability verification skipped (PRYSM_SKIP_CAPABILITY_CHECK=true)")
		return nil
	}

	requiredCaps := []int{
		unix.CAP_BPF,        // Load eBPF programs
		unix.CAP_SYS_ADMIN,  // Attach to kernel hooks
		unix.CAP_NET_ADMIN,  // Network monitoring
		unix.CAP_SYS_PTRACE, // Process monitoring
	}

	missing := make([]int, 0)
	for _, cap := range requiredCaps {
		if !hasCapability(cap) {
			if cap == unix.CAP_BPF {
				log.Printf("Warning: CAP_BPF not present; continuing with reduced visibility")
				continue
			}
			missing = append(missing, cap)
		}
	}

	if len(missing) > 0 {
		log.Printf("Warning: missing capabilities %v - eBPF functionality may be limited", missing)
		// Don't fail if capabilities are missing, just warn
		// This allows the collector to run in containerized environments
		// where full capabilities might not be available
		return nil
	}

	return nil
}

// hasCapability checks if the current process has a specific capability
func hasCapability(cap int) bool {
	// Read capability sets from /proc/self/status
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "CapEff:") {
			capHex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			return checkCapInHex(capHex, cap)
		}
	}
	return false
}

// checkCapInHex checks if a capability bit is set in a hex capability mask
func checkCapInHex(capHex string, cap int) bool {
	// Remove 0x prefix if present
	capHex = strings.TrimPrefix(capHex, "0x")

	// Parse hex string to integer
	capMask := uint64(0)
	for _, char := range capHex {
		digit := uint64(0)
		switch {
		case char >= '0' && char <= '9':
			digit = uint64(char - '0')
		case char >= 'a' && char <= 'f':
			digit = uint64(char - 'a' + 10)
		case char >= 'A' && char <= 'F':
			digit = uint64(char - 'A' + 10)
		default:
			return false
		}
		capMask = capMask*16 + digit
	}

	// Check if the capability bit is set
	return (capMask & (1 << uint(cap))) != 0
}

// SecureMount validates and secures filesystem mounts
func SecureMount(source, target, fstype string, flags uintptr) error {
	// Validate mount paths
	if !isValidMountPath(source) || !isValidMountPath(target) {
		return fmt.Errorf("invalid mount path")
	}

	// Ensure target directory exists
	if err := os.MkdirAll(target, 0755); err != nil {
		return fmt.Errorf("failed to create mount target: %w", err)
	}

	// Add security flags
	secureFlags := flags | unix.MS_NOSUID | unix.MS_NODEV
	if fstype != "bpf" {
		secureFlags |= unix.MS_RDONLY // Read-only for non-BPF mounts
	}

	// Perform the mount
	if err := unix.Mount(source, target, fstype, secureFlags, ""); err != nil {
		return fmt.Errorf("mount failed: %w", err)
	}

	return nil
}

// isValidMountPath validates a filesystem path for mounting
func isValidMountPath(path string) bool {
	// Must be absolute path
	if !filepath.IsAbs(path) {
		return false
	}

	// No path traversal
	if strings.Contains(path, "..") {
		return false
	}

	// Must be within allowed prefixes
	allowedPrefixes := []string{
		"/sys/fs/bpf",
		"/lib/modules",
		"/usr/src",
		"/proc",
		"/var/log",
	}

	for _, prefix := range allowedPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// GenerateSecureToken generates a cryptographically secure token
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	return hex.EncodeToString(bytes), nil
}

// SecureCompare performs constant-time comparison to prevent timing attacks
func SecureCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CalculateFileHash calculates SHA256 hash of a file for integrity verification
func CalculateFileHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getEnvAsInt reads an integer from environment variable with a default value
func getEnvAsInt(key string, defaultValue int) int {
	valStr := strings.TrimSpace(os.Getenv(key))
	if valStr == "" {
		return defaultValue
	}
	val, err := strconv.Atoi(valStr)
	if err != nil {
		log.Printf("Invalid value for %s: %s, using default: %d", key, valStr, defaultValue)
		return defaultValue
	}
	return val
}
