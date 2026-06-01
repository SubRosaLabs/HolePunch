// Package auth provides Ed25519 operator authentication for HolePunch.
//
// Operators are identified by long-lived Ed25519 keypairs. The orchestrator
// holds an authorized_keys file (one base64-encoded pubkey per line); a client
// proves possession of a matching private key by signing a server-generated
// session nonce. Without a key, a client is treated as a passive agent.
package auth

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	PublicKeySize = ed25519.PublicKeySize // 32
	SeedSize      = ed25519.SeedSize      // 32 (what we persist on disk)
	SignatureSize = ed25519.SignatureSize // 64
)

// sigPrefix domain-separates auth signatures from any other Ed25519 signing
// this codebase might do later. A signature over (sigPrefix || nonce || id)
// won't accidentally satisfy a different protocol that signs (nonce || id).
var sigPrefix = []byte("HolePunch-Auth-v1\x00")

// AuthorizedKeys maps an Ed25519 public key to its optional label (the inline
// comment after `#` on its line in the authorized_keys file). The label is
// only used for logging; membership in the map is what grants the operator
// role.
type AuthorizedKeys map[[PublicKeySize]byte]string

// Contains reports whether pub is authorized.
func (a AuthorizedKeys) Contains(pub [PublicKeySize]byte) bool {
	_, ok := a[pub]
	return ok
}

// LoadAuthorizedKeys parses path as one-base64-key-per-line. Lines that are
// blank or begin with `#` are skipped; an inline `# label` after a key sets
// that key's label. A missing file is NOT an error — callers receive an empty
// map and decide how to react (the orchestrator warns and runs with zero
// operators allowed).
func LoadAuthorizedKeys(path string) (AuthorizedKeys, error) {
	keys := AuthorizedKeys{}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return keys, nil
		}
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		label := ""
		if idx := strings.Index(raw, "#"); idx >= 0 {
			label = strings.TrimSpace(raw[idx+1:])
			raw = strings.TrimSpace(raw[:idx])
		}

		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("authorized_keys line %d: invalid base64: %w", lineNo, err)
		}
		if len(decoded) != PublicKeySize {
			return nil, fmt.Errorf("authorized_keys line %d: expected %d-byte key, got %d", lineNo, PublicKeySize, len(decoded))
		}

		var key [PublicKeySize]byte
		copy(key[:], decoded)
		keys[key] = label
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return keys, nil
}

// GenerateKeypair produces a fresh Ed25519 keypair from crypto/rand.
func GenerateKeypair() (pub [PublicKeySize]byte, priv ed25519.PrivateKey, err error) {
	p, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pub, nil, err
	}
	copy(pub[:], p)
	return pub, k, nil
}

// SavePrivateKey writes the 32-byte Ed25519 seed to path with 0600 perms.
// We persist the seed (smallest unambiguous form) rather than the 64-byte
// expanded private key; LoadPrivateKey re-expands.
func SavePrivateKey(path string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key length: %d", len(priv))
	}
	return os.WriteFile(path, priv.Seed(), 0600)
}

// LoadPrivateKey reads a 32-byte seed file and returns the expanded private
// key. On Unix-like OSes, refuses files whose group/world bits are set (same
// stance ssh takes) — silent permissive loading is a footgun.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("private key %s has too-open permissions %o (want 0600)", path, info.Mode().Perm())
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) != SeedSize {
		return nil, fmt.Errorf("private key %s: expected %d-byte seed, got %d", path, SeedSize, len(data))
	}
	return ed25519.NewKeyFromSeed(data), nil
}

// SavePublicKey writes pub in authorized_keys line format (base64, optional
// trailing `# label`, single trailing newline) to path with 0644 perms.
func SavePublicKey(path string, pub [PublicKeySize]byte, label string) error {
	line := base64.StdEncoding.EncodeToString(pub[:])
	if label != "" {
		line += " # " + label
	}
	line += "\n"
	return os.WriteFile(path, []byte(line), 0644)
}

// EncodePublicKey returns the base64 form used in authorized_keys lines.
func EncodePublicKey(pub [PublicKeySize]byte) string {
	return base64.StdEncoding.EncodeToString(pub[:])
}

// Fingerprint returns a short, log-friendly identifier (first 12 chars of the
// base64 pubkey). Enough to disambiguate without dumping the whole 44-char key.
func Fingerprint(pub [PublicKeySize]byte) string {
	return EncodePublicKey(pub)[:12]
}

// Sign produces a signature over (sigPrefix || sessionNonce || clientID).
// Both sides MUST construct the message identically.
func Sign(priv ed25519.PrivateKey, sessionNonce [32]byte, clientID [32]byte) [SignatureSize]byte {
	var out [SignatureSize]byte
	copy(out[:], ed25519.Sign(priv, signedMessage(sessionNonce, clientID)))
	return out
}

// Verify checks sig against (sigPrefix || sessionNonce || clientID) using pub.
func Verify(pub [PublicKeySize]byte, sessionNonce [32]byte, clientID [32]byte, sig [SignatureSize]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(pub[:]), signedMessage(sessionNonce, clientID), sig[:])
}

func signedMessage(sessionNonce [32]byte, clientID [32]byte) []byte {
	msg := make([]byte, 0, len(sigPrefix)+64)
	msg = append(msg, sigPrefix...)
	msg = append(msg, sessionNonce[:]...)
	msg = append(msg, clientID[:]...)
	return msg
}
