package main

import (
	"bytes"
	"testing"
)

func TestDeriveEventKey(t *testing.T) {
	key1 := DeriveEventKey("password", "salt1")
	key2 := DeriveEventKey("password", "salt1")
	key3 := DeriveEventKey("password", "salt2")

	if len(key1) != 32 {
		t.Errorf("DeriveEventKey returned key length %d, want 32", len(key1))
	}
	if !bytes.Equal(key1, key2) {
		t.Error("same password+salt should produce same key")
	}
	if bytes.Equal(key1, key3) {
		t.Error("different salt should produce different key")
	}
}

func TestSecureRandom(t *testing.T) {
	b1, err := SecureRandom(16)
	if err != nil {
		t.Fatalf("SecureRandom failed: %v", err)
	}
	if len(b1) != 16 {
		t.Errorf("SecureRandom(16) returned %d bytes", len(b1))
	}

	b2, err := SecureRandom(16)
	if err != nil {
		t.Fatalf("SecureRandom failed: %v", err)
	}
	if bytes.Equal(b1, b2) {
		t.Error("SecureRandom should produce different values each call")
	}
}

func TestNewEventDecryptor(t *testing.T) {
	ed := NewEventDecryptor()
	if ed == nil {
		t.Fatal("NewEventDecryptor returned nil")
	}
	if ed.keys == nil {
		t.Error("decryptor keys map should be initialized")
	}
}

func TestEventDecryptorAddKey(t *testing.T) {
	ed := NewEventDecryptor()
	key := DeriveEventKey("test-password", "test-salt")
	var keyID [16]byte
	copy(keyID[:], key[:16])

	err := ed.AddKey(keyID, key)
	if err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
}

func TestNewMemoryProtector(t *testing.T) {
	mp := NewMemoryProtector()
	if mp == nil {
		t.Fatal("NewMemoryProtector returned nil")
	}
	if mp.securePages == nil {
		t.Error("securePages map should be initialized")
	}
}

func TestNewSecureRingBuffer(t *testing.T) {
	srb, err := NewSecureRingBuffer("test-password")
	if err != nil {
		t.Fatalf("NewSecureRingBuffer failed: %v", err)
	}
	if srb == nil {
		t.Fatal("NewSecureRingBuffer returned nil")
	}
	if srb.gcm == nil {
		t.Error("GCM cipher should be initialized")
	}
}
