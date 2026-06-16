package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeygenRoundtrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	dir := t.TempDir()
	privPath := filepath.Join(dir, "operator.key")
	pubPath := privPath + ".pub"

	if err := SavePrivateKey(privPath, priv); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	if err := SavePublicKey(pubPath, pub, "test-operator"); err != nil {
		t.Fatalf("SavePublicKey: %v", err)
	}

	loadedPriv, err := LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}
	if string(loadedPriv.Seed()) != string(priv.Seed()) {
		t.Error("loaded private key seed differs from saved one")
	}

	// authorized_keys should load the saved pub line.
	authPath := filepath.Join(dir, "authorized_keys")
	pubData, _ := os.ReadFile(pubPath)
	if err := os.WriteFile(authPath, pubData, 0644); err != nil {
		t.Fatalf("write authorized_keys: %v", err)
	}
	keys, err := LoadAuthorizedKeys(authPath)
	if err != nil {
		t.Fatalf("LoadAuthorizedKeys: %v", err)
	}
	if !keys.Contains(pub) {
		t.Error("saved pubkey not present after roundtrip through authorized_keys")
	}
	if keys[pub] != "test-operator" {
		t.Errorf("label not preserved: got %q, want %q", keys[pub], "test-operator")
	}
}

func TestLoadAuthorizedKeysVariants(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	pubA, _, _ := GenerateKeypair()
	pubB, _, _ := GenerateKeypair()

	contents := strings.Join([]string{
		"# top-of-file comment",
		"",
		EncodePublicKey(pubA) + "  # alice",
		"   ",
		EncodePublicKey(pubB), // no comment
		"# trailing comment",
	}, "\n")
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	keys, err := LoadAuthorizedKeys(path)
	if err != nil {
		t.Fatalf("LoadAuthorizedKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
	if keys[pubA] != "alice" {
		t.Errorf("label A: got %q, want %q", keys[pubA], "alice")
	}
	if keys[pubB] != "" {
		t.Errorf("label B: got %q, want empty", keys[pubB])
	}
}

func TestLoadAuthorizedKeysMissingFile(t *testing.T) {
	keys, err := LoadAuthorizedKeys("/nonexistent/path/authorized_keys")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("missing file should produce empty map, got %d", len(keys))
	}
}

func TestLoadAuthorizedKeysMalformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte("not-base64!@#$\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadAuthorizedKeys(path); err == nil {
		t.Error("expected error for non-base64 content")
	}
}

func TestLoadAuthorizedKeysWrongLength(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if err := os.WriteFile(path, []byte(short+"\n"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadAuthorizedKeys(path); err == nil {
		t.Error("expected error for wrong-length key")
	}
}

func TestSignVerifyRoundtrip(t *testing.T) {
	_, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	var pub [PublicKeySize]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))

	var nonce, clientID [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
		clientID[i] = byte(i * 2)
	}

	sig := Sign(priv, nonce, clientID)
	if !Verify(pub, nonce, clientID, sig) {
		t.Fatal("Verify rejected a signature it just produced")
	}

	// Tamper with each input; verification must fail.
	badNonce := nonce
	badNonce[0] ^= 0x01
	if Verify(pub, badNonce, clientID, sig) {
		t.Error("Verify accepted signature with mutated nonce")
	}

	badID := clientID
	badID[0] ^= 0x01
	if Verify(pub, nonce, badID, sig) {
		t.Error("Verify accepted signature with mutated clientID")
	}

	badSig := sig
	badSig[0] ^= 0x01
	if Verify(pub, nonce, clientID, badSig) {
		t.Error("Verify accepted mutated signature")
	}
}

func TestSignDomainSeparated(t *testing.T) {
	// A signature produced via auth.Sign must NOT verify when checked over
	// the bare nonce||clientID (no sigPrefix). This guards against future
	// protocol reuse that signs a similarly-shaped message.
	_, priv, _ := GenerateKeypair()
	var pub [PublicKeySize]byte
	copy(pub[:], priv.Public().(ed25519.PublicKey))

	var nonce, clientID [32]byte
	for i := range nonce {
		nonce[i] = byte(i)
		clientID[i] = byte(i + 100)
	}
	sig := Sign(priv, nonce, clientID)

	rawMsg := append(append([]byte{}, nonce[:]...), clientID[:]...)
	if ed25519.Verify(ed25519.PublicKey(pub[:]), rawMsg, sig[:]) {
		t.Error("signature verified over un-prefixed message — domain separation broken")
	}
}

func TestPrivateKeyPermsEnforced(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm enforcement only applies on Unix-like OSes")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "operator.key")

	_, priv, _ := GenerateKeypair()
	if err := SavePrivateKey(path, priv); err != nil {
		t.Fatalf("SavePrivateKey: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadPrivateKey(path); err == nil {
		t.Error("LoadPrivateKey accepted a world-readable key file")
	}
}

func TestFingerprintIsShort(t *testing.T) {
	pub, _, _ := GenerateKeypair()
	fp := Fingerprint(pub)
	if len(fp) != 12 {
		t.Errorf("Fingerprint length: got %d, want 12", len(fp))
	}
}
