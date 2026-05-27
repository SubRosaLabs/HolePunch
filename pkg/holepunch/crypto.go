// Package holepunch provides UDP hole punching functionality with crypto
package holepunch

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// constants
const (
	RekeyAfterTime   = 120 * time.Second // Rekey after 2 minutes
	RejectAfterTime  = 180 * time.Second // Reject session after 3 minutes
	KeepaliveTimeout = 25 * time.Second  // Keepalive interval
	ReplayWindowSize = 2048              // Replay protection window size
)

// KeyPair holds a public/private key pair for X25519
type KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

// GenerateKeyPair generates a new X25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, err
	}

	// Clamp the private key per X25519 spec
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)
	return kp, nil
}

// ComputeSharedSecret computes the shared secret using X25519
func ComputeSharedSecret(privateKey, peerPublicKey *[32]byte) ([32]byte, error) {
	var sharedSecret [32]byte
	out, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return sharedSecret, err
	}
	copy(sharedSecret[:], out)
	return sharedSecret, nil
}

// Encryptor handles encryption/decryption with replay protection
type Encryptor struct {
	cipher      cipher.AEAD
	sendCounter uint64
	recvWindow  *ReplayWindow
	createdAt   time.Time
	mu          sync.Mutex
}

// ReplayWindow implements sliding window replay protection
type ReplayWindow struct {
	lastSeq uint64
	bitmap  [ReplayWindowSize / 64]uint64
	mu      sync.Mutex
}

// NewReplayWindow creates a new replay protection window
func NewReplayWindow() *ReplayWindow {
	return &ReplayWindow{}
}

// Check returns true if the sequence number is valid (not a replay)
func (w *ReplayWindow) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq == 0 {
		return false
	}

	if seq > w.lastSeq {
		// New packet, update window
		diff := seq - w.lastSeq
		if diff >= ReplayWindowSize {
			// Clear entire window
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			// Shift window
			for i := uint64(0); i < diff; i++ {
				idx := (w.lastSeq + i + 1) % ReplayWindowSize
				w.bitmap[idx/64] &^= 1 << (idx % 64)
			}
		}
		w.lastSeq = seq
		idx := seq % ReplayWindowSize
		w.bitmap[idx/64] |= 1 << (idx % 64)
		return true
	}

	// Check if within window
	if w.lastSeq-seq >= ReplayWindowSize {
		return false // Too old
	}

	idx := seq % ReplayWindowSize
	if w.bitmap[idx/64]&(1<<(idx%64)) != 0 {
		return false // Already seen
	}

	w.bitmap[idx/64] |= 1 << (idx % 64)
	return true
}

// NewEncryptor creates a new encryptor from a shared secret ()
func NewEncryptor(sharedSecret [32]byte) (*Encryptor, error) {
	c, err := chacha20poly1305.NewX(sharedSecret[:])
	if err != nil {
		return nil, err
	}
	return &Encryptor{
		cipher:      c,
		sendCounter: 0,
		recvWindow:  NewReplayWindow(),
		createdAt:   time.Now(),
	}, nil
}

// NeedsRekey returns true if session should be rekeyed ()
func (e *Encryptor) NeedsRekey() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Since(e.createdAt) > RekeyAfterTime
}

// IsExpired returns true if the session is too old
func (e *Encryptor) IsExpired() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Since(e.createdAt) > RejectAfterTime
}

// Encrypt encrypts plaintext with counter-based nonce ()
func (e *Encryptor) Encrypt(plaintext []byte) (nonce [24]byte, ciphertext []byte, err error) {
	e.mu.Lock()
	e.sendCounter++
	counter := e.sendCounter
	e.mu.Unlock()

	// Counter-based nonce: first 8 bytes = counter, rest = random
	binary.LittleEndian.PutUint64(nonce[:8], counter)
	if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
		return nonce, nil, err
	}

	ciphertext = e.cipher.Seal(nil, nonce[:], plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext with replay protection ()
func (e *Encryptor) Decrypt(nonce [24]byte, ciphertext []byte) ([]byte, error) {
	// Extract counter for replay protection
	counter := binary.LittleEndian.Uint64(nonce[:8])

	// Check replay window
	if !e.recvWindow.Check(counter) {
		return nil, errors.New("replay attack detected")
	}

	plaintext, err := e.cipher.Open(nil, nonce[:], ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: " + err.Error())
	}
	return plaintext, nil
}

// GenerateClientID generates a random 32-byte client ID
func GenerateClientID() ([32]byte, error) {
	var id [32]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	return id, nil
}
