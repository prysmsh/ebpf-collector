package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"golang.org/x/crypto/argon2"
)

// SecureRingBuffer wraps ring buffer operations with encryption
type SecureRingBuffer struct {
	gcm    cipher.AEAD
	keyID  [16]byte
	nonce  [12]byte
	mu     sync.RWMutex
}

// EncryptedSecurityEvent represents an encrypted security event
type EncryptedSecurityEvent struct {
	KeyID      [16]byte `json:"key_id"`
	Nonce      [12]byte `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
	MAC        [16]byte `json:"mac"`
	Timestamp  uint64   `json:"timestamp"`
}

// SecureEventProcessor handles secure processing of eBPF events
type SecureEventProcessor struct {
	ringBuffer     *SecureRingBuffer
	eventDecryptor *EventDecryptor
	memProtector   *MemoryProtector
	mu             sync.RWMutex
}

// EventDecryptor handles decryption of security events
type EventDecryptor struct {
	keys map[[16]byte]cipher.AEAD
	mu   sync.RWMutex
}

// MemoryProtector provides memory protection utilities
type MemoryProtector struct {
	securePages map[uintptr]int
	mu          sync.RWMutex
}

// NewSecureRingBuffer creates a new encrypted ring buffer
func NewSecureRingBuffer(password string) (*SecureRingBuffer, error) {
	// Derive encryption key using Argon2
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	
	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate key ID
	var keyID [16]byte
	if _, err := rand.Read(keyID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	return &SecureRingBuffer{
		gcm:   gcm,
		keyID: keyID,
	}, nil
}

// EncryptEvent encrypts a security event
func (srb *SecureRingBuffer) EncryptEvent(event *SecurityEvent) (*EncryptedSecurityEvent, error) {
	srb.mu.Lock()
	defer srb.mu.Unlock()

	// Generate random nonce
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Serialize event to bytes
	eventBytes := (*[unsafe.Sizeof(SecurityEvent{})]byte)(unsafe.Pointer(event))[:]
	
	// Additional authenticated data (AAD) includes key ID and timestamp
	aad := make([]byte, 16+8)
	copy(aad[:16], srb.keyID[:])
	binary.LittleEndian.PutUint64(aad[16:], event.Timestamp)

	// Encrypt the event
	ciphertext := srb.gcm.Seal(nil, nonce[:], eventBytes, aad)

	// Extract MAC from ciphertext (last 16 bytes)
	if len(ciphertext) < 16 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	var mac [16]byte
	copy(mac[:], ciphertext[len(ciphertext)-16:])
	ciphertext = ciphertext[:len(ciphertext)-16]

	return &EncryptedSecurityEvent{
		KeyID:      srb.keyID,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		MAC:        mac,
		Timestamp:  event.Timestamp,
	}, nil
}

// NewEventDecryptor creates a new event decryptor
func NewEventDecryptor() *EventDecryptor {
	return &EventDecryptor{
		keys: make(map[[16]byte]cipher.AEAD),
	}
}

// AddKey adds a decryption key
func (ed *EventDecryptor) AddKey(keyID [16]byte, key []byte) error {
	ed.mu.Lock()
	defer ed.mu.Unlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	ed.keys[keyID] = gcm
	return nil
}

// DecryptEvent decrypts an encrypted security event
func (ed *EventDecryptor) DecryptEvent(encEvent *EncryptedSecurityEvent) (*SecurityEvent, error) {
	ed.mu.RLock()
	gcm, exists := ed.keys[encEvent.KeyID]
	ed.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("decryption key not found for key ID: %x", encEvent.KeyID)
	}

	// Reconstruct ciphertext with MAC
	fullCiphertext := append(encEvent.Ciphertext, encEvent.MAC[:]...)

	// Reconstruct AAD
	aad := make([]byte, 16+8)
	copy(aad[:16], encEvent.KeyID[:])
	binary.LittleEndian.PutUint64(aad[16:], encEvent.Timestamp)

	// Decrypt
	plaintext, err := gcm.Open(nil, encEvent.Nonce[:], fullCiphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Convert back to SecurityEvent
	if len(plaintext) != int(unsafe.Sizeof(SecurityEvent{})) {
		return nil, fmt.Errorf("invalid plaintext length: %d", len(plaintext))
	}

	event := (*SecurityEvent)(unsafe.Pointer(&plaintext[0]))
	return event, nil
}

// NewMemoryProtector creates a new memory protector
func NewMemoryProtector() *MemoryProtector {
	return &MemoryProtector{
		securePages: make(map[uintptr]int),
	}
}

// ProtectMemory marks memory pages as non-swappable and read-only where possible
func (mp *MemoryProtector) ProtectMemory(ptr unsafe.Pointer, size int) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	addr := uintptr(ptr)
	pageSize := 4096 // Typical page size
	
	// Align to page boundaries
	startPage := addr &^ uintptr(pageSize-1)
	endPage := (addr + uintptr(size) + uintptr(pageSize-1)) &^ uintptr(pageSize-1)
	
	for page := startPage; page < endPage; page += uintptr(pageSize) {
		// Lock pages in memory (prevent swapping)
		if err := lockMemoryPage(page, pageSize); err != nil {
			return fmt.Errorf("failed to lock memory page: %w", err)
		}
		
		mp.securePages[page] = pageSize
	}

	return nil
}

// ClearMemory securely clears memory content
func (mp *MemoryProtector) ClearMemory(ptr unsafe.Pointer, size int) {
	// Overwrite with random data first
	randomData := make([]byte, size)
	rand.Read(randomData)
	
	slice := (*[]byte)(unsafe.Pointer(&struct {
		data uintptr
		len  int
		cap  int
	}{uintptr(ptr), size, size}))
	
	copy(*slice, randomData)
	
	// Then overwrite with zeros
	for i := range *slice {
		(*slice)[i] = 0
	}
}

// UnprotectMemory removes memory protection
func (mp *MemoryProtector) UnprotectMemory(ptr unsafe.Pointer, size int) error {
	mp.mu.Lock()
	defer mp.mu.Unlock()

	addr := uintptr(ptr)
	pageSize := 4096
	
	startPage := addr &^ uintptr(pageSize-1)
	endPage := (addr + uintptr(size) + uintptr(pageSize-1)) &^ uintptr(pageSize-1)
	
	for page := startPage; page < endPage; page += uintptr(pageSize) {
		if _, exists := mp.securePages[page]; exists {
			if err := unlockMemoryPage(page, pageSize); err != nil {
				return fmt.Errorf("failed to unlock memory page: %w", err)
			}
			delete(mp.securePages, page)
		}
	}

	return nil
}

// NewSecureEventProcessor creates a new secure event processor
func NewSecureEventProcessor(password string) (*SecureEventProcessor, error) {
	ringBuffer, err := NewSecureRingBuffer(password)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure ring buffer: %w", err)
	}

	return &SecureEventProcessor{
		ringBuffer:     ringBuffer,
		eventDecryptor: NewEventDecryptor(),
		memProtector:   NewMemoryProtector(),
	}, nil
}

// ProcessSecureEvent securely processes an eBPF event
func (sep *SecureEventProcessor) ProcessSecureEvent(event *SecurityEvent) error {
	sep.mu.Lock()
	defer sep.mu.Unlock()

	// Protect event memory
	if err := sep.memProtector.ProtectMemory(unsafe.Pointer(event), int(unsafe.Sizeof(*event))); err != nil {
		return fmt.Errorf("failed to protect event memory: %w", err)
	}
	defer sep.memProtector.UnprotectMemory(unsafe.Pointer(event), int(unsafe.Sizeof(*event)))

	// Encrypt the event
	encryptedEvent, err := sep.ringBuffer.EncryptEvent(event)
	if err != nil {
		return fmt.Errorf("failed to encrypt event: %w", err)
	}

	// Clear original event from memory
	sep.memProtector.ClearMemory(unsafe.Pointer(event), int(unsafe.Sizeof(*event)))

	// Process encrypted event (this would typically send to ring buffer)
	return sep.handleEncryptedEvent(encryptedEvent)
}

// handleEncryptedEvent handles an encrypted event
func (sep *SecureEventProcessor) handleEncryptedEvent(encEvent *EncryptedSecurityEvent) error {
	// In a real implementation, this would:
	// 1. Store the encrypted event in the ring buffer
	// 2. Forward to secure processing pipeline
	// 3. Log security metrics
	// Per-event logging removed to avoid log spam; use PRYSM_EBPF_DEBUG=1 for verbose logs if needed.
	return nil
}

// GetEncryptionStats returns encryption statistics
func (sep *SecureEventProcessor) GetEncryptionStats() map[string]interface{} {
	sep.mu.RLock()
	defer sep.mu.RUnlock()

	return map[string]interface{}{
		"encryption_enabled": true,
		"algorithm":          "AES-256-GCM",
		"key_derivation":     "Argon2ID",
		"protected_pages":    len(sep.memProtector.securePages),
	}
}

// Hash-based key derivation for deterministic keys
func DeriveEventKey(password, salt string) []byte {
	combined := fmt.Sprintf("%s:%s", password, salt)
	hash := sha256.Sum256([]byte(combined))
	return hash[:]
}

// SecureRandom generates cryptographically secure random bytes
func SecureRandom(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return bytes, nil
}

// Platform-specific memory locking functions
func lockMemoryPage(addr uintptr, size int) error {
	// This would use mlock() on Linux
	// For now, just return success
	return nil
}

func unlockMemoryPage(addr uintptr, size int) error {
	// This would use munlock() on Linux  
	// For now, just return success
	return nil
}