package holepunch

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	// Keys should be different
	if bytes.Equal(kp1.PrivateKey[:], kp2.PrivateKey[:]) {
		t.Error("Generated identical private keys")
	}
	if bytes.Equal(kp1.PublicKey[:], kp2.PublicKey[:]) {
		t.Error("Generated identical public keys")
	}

	// Public key should not be all zeros
	var zero [32]byte
	if bytes.Equal(kp1.PublicKey[:], zero[:]) {
		t.Error("Public key is all zeros")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	// Both sides should compute the same shared secret
	secret1, err := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret failed: %v", err)
	}

	secret2, err := ComputeSharedSecret(&kp2.PrivateKey, &kp1.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret failed: %v", err)
	}

	if !bytes.Equal(secret1[:], secret2[:]) {
		t.Error("Shared secrets don't match")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)

	enc1, _ := NewEncryptor(secret)
	enc2, _ := NewEncryptor(secret)

	plaintext := []byte("Hello, VPN tunnel!")

	nonce, ciphertext, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc2.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted text doesn't match: got %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptDecryptLargePayload(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)

	enc1, _ := NewEncryptor(secret)
	enc2, _ := NewEncryptor(secret)

	// Simulate a large IP packet (1400 bytes)
	plaintext := make([]byte, 1400)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	nonce, ciphertext, err := enc1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := enc2.Decrypt(nonce, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Error("Large payload decryption failed")
	}
}

func TestReplayProtection(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)

	enc1, _ := NewEncryptor(secret)
	enc2, _ := NewEncryptor(secret)

	plaintext := []byte("test message")

	// First encryption
	nonce1, ciphertext1, _ := enc1.Encrypt(plaintext)

	// First decryption should succeed
	_, err := enc2.Decrypt(nonce1, ciphertext1)
	if err != nil {
		t.Fatalf("First decrypt failed: %v", err)
	}

	// Replay of same packet should fail
	_, err = enc2.Decrypt(nonce1, ciphertext1)
	if err == nil {
		t.Error("Replay attack not detected")
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)

	enc1, _ := NewEncryptor(secret)
	enc2, _ := NewEncryptor(secret)

	// Send 3 packets
	nonce1, ct1, _ := enc1.Encrypt([]byte("packet 1"))
	nonce2, ct2, _ := enc1.Encrypt([]byte("packet 2"))
	nonce3, ct3, _ := enc1.Encrypt([]byte("packet 3"))

	// Receive out of order: 3, 1, 2
	_, err := enc2.Decrypt(nonce3, ct3)
	if err != nil {
		t.Fatalf("Decrypt packet 3 failed: %v", err)
	}

	_, err = enc2.Decrypt(nonce1, ct1)
	if err != nil {
		t.Fatalf("Decrypt packet 1 (out of order) failed: %v", err)
	}

	_, err = enc2.Decrypt(nonce2, ct2)
	if err != nil {
		t.Fatalf("Decrypt packet 2 (out of order) failed: %v", err)
	}

	// Replay any should fail
	_, err = enc2.Decrypt(nonce1, ct1)
	if err == nil {
		t.Error("Replay of packet 1 not detected")
	}
}

func TestReplayWindowSliding(t *testing.T) {
	w := NewReplayWindow()

	// Accept first packet
	if !w.Check(1) {
		t.Error("Should accept seq 1")
	}

	// Reject replay
	if w.Check(1) {
		t.Error("Should reject replay of seq 1")
	}

	// Accept next
	if !w.Check(2) {
		t.Error("Should accept seq 2")
	}

	// Accept out of order within window
	if !w.Check(100) {
		t.Error("Should accept seq 100")
	}

	// Accept packet between 2 and 100
	if !w.Check(50) {
		t.Error("Should accept seq 50 (within window)")
	}

	// Reject replay
	if w.Check(50) {
		t.Error("Should reject replay of seq 50")
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	w := NewReplayWindow()

	// Accept a high sequence number
	if !w.Check(ReplayWindowSize + 100) {
		t.Error("Should accept high seq")
	}

	// Reject packet outside window (too old)
	if w.Check(1) {
		t.Error("Should reject seq 1 as too old")
	}
}

func TestCounterBasedNonce(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)

	enc, _ := NewEncryptor(secret)

	// Encrypt multiple messages
	nonce1, _, _ := enc.Encrypt([]byte("msg1"))
	nonce2, _, _ := enc.Encrypt([]byte("msg2"))
	nonce3, _, _ := enc.Encrypt([]byte("msg3"))

	// First 8 bytes should be incrementing counters
	if bytes.Equal(nonce1[:8], nonce2[:8]) {
		t.Error("Nonce counters should be different")
	}
	if bytes.Equal(nonce2[:8], nonce3[:8]) {
		t.Error("Nonce counters should be different")
	}
}

// TestForgedHighCounterDoesNotLockOutValidPackets guards the AEAD-first
// Decrypt ordering. Previously, the replay window advanced on counter parse
// alone, so a forged packet with a high counter could cause subsequent valid
// packets to be rejected as "too old". The fix runs cipher.Open BEFORE
// touching the window.
func TestForgedHighCounterDoesNotLockOutValidPackets(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)
	enc1, _ := NewEncryptor(secret)
	enc2, _ := NewEncryptor(secret)

	validNonce, validCT, err := enc1.Encrypt([]byte("legit"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// Forge a "packet" with a high counter and a bogus ciphertext.
	// The receiver should reject it AND keep the replay window intact.
	var forgedNonce [24]byte
	binary.LittleEndian.PutUint64(forgedNonce[:8], uint64(ReplayWindowSize)*4)
	forgedCT := []byte("not-a-valid-aead-tagged-payload-xxxxxxxxxx")

	if _, err := enc2.Decrypt(forgedNonce, forgedCT); err == nil {
		t.Fatal("forged packet should fail decrypt")
	}

	// The legitimate packet (counter=1) must still decrypt.
	if _, err := enc2.Decrypt(validNonce, validCT); err != nil {
		t.Fatalf("valid packet was locked out by forged advance: %v", err)
	}
}

func TestGenerateClientID(t *testing.T) {
	id1, err := GenerateClientID()
	if err != nil {
		t.Fatalf("GenerateClientID failed: %v", err)
	}

	id2, err := GenerateClientID()
	if err != nil {
		t.Fatalf("GenerateClientID failed: %v", err)
	}

	if bytes.Equal(id1[:], id2[:]) {
		t.Error("Generated identical client IDs")
	}
}

func TestEncryptorConcurrency(t *testing.T) {
	kp1, _ := GenerateKeyPair()
	kp2, _ := GenerateKeyPair()

	secret, _ := ComputeSharedSecret(&kp1.PrivateKey, &kp2.PublicKey)

	enc, _ := NewEncryptor(secret)

	// Concurrent encryptions should not panic
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(n int) {
			_, _, err := enc.Encrypt([]byte("concurrent test"))
			if err != nil {
				t.Errorf("Concurrent encrypt %d failed: %v", n, err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent encryptions")
		}
	}
}
