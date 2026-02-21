package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SignatureManager handles eBPF program signature verification
type SignatureManager struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey // Only for development/signing
}

// ProgramSignature represents a signed eBPF program
type ProgramSignature struct {
	ProgramPath string    `json:"program_path"`
	Hash        string    `json:"hash"`
	Signature   string    `json:"signature"`
	SignedAt    time.Time `json:"signed_at"`
	SignedBy    string    `json:"signed_by"`
	Version     string    `json:"version"`
}

// SignatureManifest contains signatures for all eBPF programs
type SignatureManifest struct {
	Version      string             `json:"version"`
	CreatedAt    time.Time          `json:"created_at"`
	Programs     []ProgramSignature `json:"programs"`
	PublicKey    string             `json:"public_key"`
	ManifestHash string             `json:"manifest_hash"`
}

// NewSignatureManager creates a new signature manager
func NewSignatureManager() (*SignatureManager, error) {
	// In production, this would load a trusted public key
	publicKey, privateKey, err := loadOrGenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize signature manager: %w", err)
	}

	return &SignatureManager{
		publicKey:  publicKey,
		privateKey: privateKey,
	}, nil
}

// VerifyProgramSignatures verifies all eBPF program signatures
func (sm *SignatureManager) VerifyProgramSignatures(ebpfDir string) error {
	if strings.EqualFold(os.Getenv("PRYSM_SKIP_SIGNATURE_VERIFICATION"), "true") {
		log.Printf("Signature verification skipped (PRYSM_SKIP_SIGNATURE_VERIFICATION=true)")
		return nil
	}

	manifestPath := filepath.Join(ebpfDir, "signatures.json")

	// Load signature manifest
	manifest, err := sm.loadManifest(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to load signature manifest: %w", err)
	}

	// Verify manifest integrity
	if err := sm.verifyManifestIntegrity(manifest); err != nil {
		return fmt.Errorf("manifest integrity check failed: %w", err)
	}

	// Verify each program signature
	for _, programSig := range manifest.Programs {
		programPath := filepath.Join(ebpfDir, programSig.ProgramPath)

		if err := sm.verifyProgramSignature(programPath, programSig); err != nil {
			return fmt.Errorf("signature verification failed for %s: %w", programSig.ProgramPath, err)
		}

		log.Printf("Signature verified for eBPF program: %s", programSig.ProgramPath)
	}

	log.Printf("All eBPF program signatures verified successfully")
	return nil
}

// verifyProgramSignature verifies a single program's signature
func (sm *SignatureManager) verifyProgramSignature(programPath string, programSig ProgramSignature) error {
	// Calculate current file hash
	currentHash, err := CalculateFileHash(programPath)
	if err != nil {
		return fmt.Errorf("failed to calculate program hash: %w", err)
	}

	// Verify hash matches
	if currentHash != programSig.Hash {
		return fmt.Errorf("program hash mismatch: expected %s, got %s", programSig.Hash, currentHash)
	}

	// Decode signature
	signature, err := hex.DecodeString(programSig.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Create message to verify (hash + metadata)
	message := fmt.Sprintf("%s|%s|%s|%s",
		programSig.Hash,
		programSig.ProgramPath,
		programSig.Version,
		programSig.SignedAt.Format(time.RFC3339))

	// Verify signature
	if !ed25519.Verify(sm.publicKey, []byte(message), signature) {
		return fmt.Errorf("invalid signature for program %s", programSig.ProgramPath)
	}

	// Check signature age (should not be older than 30 days)
	if time.Since(programSig.SignedAt) > 30*24*time.Hour {
		return fmt.Errorf("signature for %s is too old", programSig.ProgramPath)
	}

	return nil
}

// verifyManifestIntegrity verifies the signature manifest itself
func (sm *SignatureManager) verifyManifestIntegrity(manifest *SignatureManifest) error {
	// Verify public key matches
	manifestPubKey, err := hex.DecodeString(manifest.PublicKey)
	if err != nil {
		return fmt.Errorf("invalid public key in manifest: %w", err)
	}

	if !ed25519.PublicKey(manifestPubKey).Equal(sm.publicKey) {
		return fmt.Errorf("manifest public key does not match trusted key")
	}

	// Calculate manifest hash (excluding the hash field itself)
	manifestCopy := *manifest
	manifestCopy.ManifestHash = ""

	manifestData, err := json.Marshal(manifestCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	hash := sha256.Sum256(manifestData)
	expectedHash := hex.EncodeToString(hash[:])

	if expectedHash != manifest.ManifestHash {
		return fmt.Errorf("manifest hash verification failed")
	}

	return nil
}

// loadManifest loads the signature manifest from file
func (sm *SignatureManager) loadManifest(manifestPath string) (*SignatureManifest, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest file: %w", err)
	}

	var manifest SignatureManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// SignPrograms signs all eBPF programs and creates a manifest (development only)
func (sm *SignatureManager) SignPrograms(ebpfDir string) error {
	if sm.privateKey == nil {
		return fmt.Errorf("no private key available for signing")
	}

	programs := []string{
		"process_monitor.c",
		"network_monitor.c",
		"file_monitor.c",
		"syscall_monitor.c",
	}

	var programSignatures []ProgramSignature
	signedAt := time.Now().UTC()

	for _, program := range programs {
		programPath := filepath.Join(ebpfDir, program)

		// Check if program exists
		if _, err := os.Stat(programPath); os.IsNotExist(err) {
			log.Printf("Skipping non-existent program: %s", program)
			continue
		}

		// Calculate program hash
		hash, err := CalculateFileHash(programPath)
		if err != nil {
			return fmt.Errorf("failed to hash program %s: %w", program, err)
		}

		// Create signature message
		message := fmt.Sprintf("%s|%s|%s|%s",
			hash,
			program,
			"1.0.0", // version
			signedAt.Format(time.RFC3339))

		// Sign the message
		signature := ed25519.Sign(sm.privateKey, []byte(message))

		programSig := ProgramSignature{
			ProgramPath: program,
			Hash:        hash,
			Signature:   hex.EncodeToString(signature),
			SignedAt:    signedAt,
			SignedBy:    "prysm-security",
			Version:     "1.0.0",
		}

		programSignatures = append(programSignatures, programSig)
		log.Printf("Signed eBPF program: %s", program)
	}

	// Create manifest
	manifest := SignatureManifest{
		Version:   "1.0.0",
		CreatedAt: signedAt,
		Programs:  programSignatures,
		PublicKey: hex.EncodeToString(sm.publicKey),
	}

	// Calculate manifest hash
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	hash := sha256.Sum256(manifestData)
	manifest.ManifestHash = hex.EncodeToString(hash[:])

	// Save manifest
	manifestPath := filepath.Join(ebpfDir, "signatures.json")
	manifestData, err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal final manifest: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	log.Printf("Signature manifest created: %s", manifestPath)
	return nil
}

// loadOrGenerateKeyPair loads existing key pair or generates new one
func loadOrGenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	keyDir := "/etc/prysm/keys"
	pubKeyPath := filepath.Join(keyDir, "signing.pub")
	privKeyPath := filepath.Join(keyDir, "signing.key")

	// Try to load existing keys
	if _, err := os.Stat(pubKeyPath); err == nil {
		if _, err := os.Stat(privKeyPath); err == nil {
			return loadKeyPair(pubKeyPath, privKeyPath)
		}
	}

	// Generate new key pair
	log.Println("Generating new Ed25519 key pair for eBPF program signing")

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Save keys (in production, private key should be stored securely)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		log.Printf("Warning: failed to create key directory: %v", err)
	} else {
		if err := saveKeyPair(pubKeyPath, privKeyPath, publicKey, privateKey); err != nil {
			log.Printf("Warning: failed to save keys: %v", err)
		}
	}

	return publicKey, privateKey, nil
}

// loadKeyPair loads Ed25519 key pair from files
func loadKeyPair(pubKeyPath, privKeyPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	// Load public key
	pubKeyData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read public key: %w", err)
	}

	publicKey, err := hex.DecodeString(string(pubKeyData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	// Load private key
	privKeyData, err := os.ReadFile(privKeyPath)
	if err != nil {
		// In production, private key might not be available (verification only)
		return ed25519.PublicKey(publicKey), nil, nil
	}

	privateKey, err := hex.DecodeString(string(privKeyData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	return ed25519.PublicKey(publicKey), ed25519.PrivateKey(privateKey), nil
}

// saveKeyPair saves Ed25519 key pair to files
func saveKeyPair(pubKeyPath, privKeyPath string, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) error {
	// Save public key
	pubKeyHex := hex.EncodeToString(publicKey)
	if err := os.WriteFile(pubKeyPath, []byte(pubKeyHex), 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	// Save private key (with restricted permissions)
	if privateKey != nil {
		privKeyHex := hex.EncodeToString(privateKey)
		if err := os.WriteFile(privKeyPath, []byte(privKeyHex), 0600); err != nil {
			return fmt.Errorf("failed to write private key: %w", err)
		}
	}

	return nil
}

// GetSigningInfo returns information about the signing configuration
func (sm *SignatureManager) GetSigningInfo() map[string]interface{} {
	return map[string]interface{}{
		"public_key":   hex.EncodeToString(sm.publicKey),
		"has_private":  sm.privateKey != nil,
		"algorithm":    "Ed25519",
		"verification": "enabled",
	}
}
