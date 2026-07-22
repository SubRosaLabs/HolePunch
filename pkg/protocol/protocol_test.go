package protocol

import (
	"bytes"
	"net"
	"testing"
)

// TestPunchInitMessageOwnsIPBytes guards against a real bug we hit:
// ParsePunchInitMessage used to construct net.IP as a slice aliasing the
// caller's data buffer. The client's receiveLoop reuses one buf across UDP
// reads, so PeerAddr.IP would later show whatever bytes happened to land at
// that offset — e.g. "22.0.4.4" instead of "172.22.0.4".
func TestPunchInitMessageOwnsIPBytes(t *testing.T) {
	srcAddr := &net.UDPAddr{IP: net.IPv4(172, 22, 0, 4), Port: 50305}
	m := &PunchInitMessage{
		PeerID:        [32]byte{0x01, 0x02},
		PeerPublicKey: [32]byte{0x03, 0x04},
		PeerAddr:      srcAddr,
	}

	wire := m.Serialize()
	payload := wire[HeaderSize:]

	// Use a buffer the caller might reuse; parse out of it, then scribble.
	buf := make([]byte, len(payload))
	copy(buf, payload)

	parsed, err := ParsePunchInitMessage(buf)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if got := parsed.PeerAddr.String(); got != "172.22.0.4:50305" {
		t.Fatalf("immediately after parse: got %q, want %q", got, "172.22.0.4:50305")
	}

	// Now simulate the receive buffer being reused for a different packet.
	for i := range buf {
		buf[i] = 0xff
	}

	// PeerAddr.IP must still reflect the original.
	if got := parsed.PeerAddr.String(); got != "172.22.0.4:50305" {
		t.Fatalf("after buffer reuse: got %q, want %q (parser is aliasing caller's buffer)", got, "172.22.0.4:50305")
	}
}

func TestRegisterAckRoundtrip(t *testing.T) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	m := &RegisterAckMessage{SessionNonce: nonce}
	wire := m.Serialize()

	hdr, err := ParseHeader(wire)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.Version != WireVersion {
		t.Errorf("Version: got %d, want %d", hdr.Version, WireVersion)
	}
	if hdr.Type != MsgTypeRegisterAck {
		t.Errorf("Type: got %d, want %d", hdr.Type, MsgTypeRegisterAck)
	}

	parsed, err := ParseRegisterAckMessage(wire[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseRegisterAckMessage: %v", err)
	}
	if !bytes.Equal(parsed.SessionNonce[:], nonce[:]) {
		t.Error("SessionNonce mismatch after roundtrip")
	}
}

func TestAuthRequestRoundtrip(t *testing.T) {
	var pub [32]byte
	var sig [64]byte
	for i := range pub {
		pub[i] = byte(i + 10)
	}
	for i := range sig {
		sig[i] = byte(i + 100)
	}
	m := &AuthRequestMessage{PublicKey: pub, Signature: sig}
	wire := m.Serialize()

	parsed, err := ParseAuthRequestMessage(wire[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseAuthRequestMessage: %v", err)
	}
	if !bytes.Equal(parsed.PublicKey[:], pub[:]) {
		t.Error("PublicKey mismatch")
	}
	if !bytes.Equal(parsed.Signature[:], sig[:]) {
		t.Error("Signature mismatch")
	}
}

func TestAuthResultRoundtrip(t *testing.T) {
	for _, granted := range []bool{true, false} {
		m := &AuthResultMessage{Granted: granted}
		wire := m.Serialize()
		parsed, err := ParseAuthResultMessage(wire[HeaderSize:])
		if err != nil {
			t.Fatalf("ParseAuthResultMessage(%v): %v", granted, err)
		}
		if parsed.Granted != granted {
			t.Errorf("Granted=%v, parsed as %v", granted, parsed.Granted)
		}
	}
}

func TestWireVersionIsThree(t *testing.T) {
	// Sanity guard: bumping this constant is a breaking protocol change.
	if WireVersion != 3 {
		t.Errorf("WireVersion: got %d, want 3", WireVersion)
	}
}

func TestAgentMetadataEncodeDecode(t *testing.T) {
	meta := &AgentMetadata{
		Username: "root",
		Hostname: "target-dc01",
		OS:       "linux",
		Arch:     "amd64",
		LocalIPs: "192.168.1.5,10.0.0.2",
	}

	encoded := meta.Encode()
	parsed := ParseAgentMetadata(encoded)
	if parsed == nil {
		t.Fatal("ParseAgentMetadata returned nil")
	}
	if parsed.Username != meta.Username {
		t.Errorf("Username: got %q, want %q", parsed.Username, meta.Username)
	}
	if parsed.Hostname != meta.Hostname {
		t.Errorf("Hostname: got %q, want %q", parsed.Hostname, meta.Hostname)
	}
	if parsed.OS != meta.OS {
		t.Errorf("OS: got %q, want %q", parsed.OS, meta.OS)
	}
	if parsed.Arch != meta.Arch {
		t.Errorf("Arch: got %q, want %q", parsed.Arch, meta.Arch)
	}
	if parsed.LocalIPs != meta.LocalIPs {
		t.Errorf("LocalIPs: got %q, want %q", parsed.LocalIPs, meta.LocalIPs)
	}
}

func TestAgentMetadataEmptyFields(t *testing.T) {
	meta := &AgentMetadata{Hostname: "box1"}
	encoded := meta.Encode()
	parsed := ParseAgentMetadata(encoded)
	if parsed == nil {
		t.Fatal("ParseAgentMetadata returned nil")
	}
	if parsed.Hostname != "box1" {
		t.Errorf("Hostname: got %q, want %q", parsed.Hostname, "box1")
	}
	if parsed.Username != "" {
		t.Errorf("Username should be empty, got %q", parsed.Username)
	}
	if parsed.OS != "" {
		t.Errorf("OS should be empty, got %q", parsed.OS)
	}
}

func TestAgentMetadataNilReturnsNil(t *testing.T) {
	if parsed := ParseAgentMetadata(nil); parsed != nil {
		t.Error("ParseAgentMetadata(nil) should return nil")
	}
	if parsed := ParseAgentMetadata([]byte{}); parsed != nil {
		t.Error("ParseAgentMetadata(empty) should return nil")
	}
}

func TestRegisterMessageWithMetadataRoundtrip(t *testing.T) {
	var id [32]byte
	var pub [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	for i := range pub {
		pub[i] = byte(i + 100)
	}

	meta := &AgentMetadata{
		Username: "admin",
		Hostname: "srv01",
		OS:       "windows",
		Arch:     "amd64",
		LocalIPs: "10.10.10.5",
	}

	msg := &RegisterMessage{ClientID: id, PublicKey: pub, Meta: meta}
	wire := msg.Serialize()

	hdr, err := ParseHeader(wire)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.Type != MsgTypeRegister {
		t.Errorf("Type: got %d, want %d", hdr.Type, MsgTypeRegister)
	}
	if hdr.Length <= 64 {
		t.Errorf("Length should be > 64 with metadata, got %d", hdr.Length)
	}

	parsed, err := ParseRegisterMessage(wire[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseRegisterMessage: %v", err)
	}
	if !bytes.Equal(parsed.ClientID[:], id[:]) {
		t.Error("ClientID mismatch")
	}
	if !bytes.Equal(parsed.PublicKey[:], pub[:]) {
		t.Error("PublicKey mismatch")
	}
	if parsed.Meta == nil {
		t.Fatal("Meta should not be nil")
	}
	if parsed.Meta.Username != "admin" {
		t.Errorf("Meta.Username: got %q, want %q", parsed.Meta.Username, "admin")
	}
	if parsed.Meta.Hostname != "srv01" {
		t.Errorf("Meta.Hostname: got %q, want %q", parsed.Meta.Hostname, "srv01")
	}
	if parsed.Meta.OS != "windows" {
		t.Errorf("Meta.OS: got %q, want %q", parsed.Meta.OS, "windows")
	}
	if parsed.Meta.LocalIPs != "10.10.10.5" {
		t.Errorf("Meta.LocalIPs: got %q, want %q", parsed.Meta.LocalIPs, "10.10.10.5")
	}
}

func TestRegisterMessageWithoutMetadataBackcompat(t *testing.T) {
	var id [32]byte
	var pub [32]byte
	for i := range id {
		id[i] = byte(i)
	}
	for i := range pub {
		pub[i] = byte(i + 50)
	}

	msg := &RegisterMessage{ClientID: id, PublicKey: pub}
	wire := msg.Serialize()

	// Without metadata the wire format should be exactly 68 bytes (4 header + 64 payload).
	if len(wire) != 68 {
		t.Errorf("wire length without metadata: got %d, want 68", len(wire))
	}

	hdr, err := ParseHeader(wire)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if hdr.Length != 64 {
		t.Errorf("Header.Length: got %d, want 64", hdr.Length)
	}

	parsed, err := ParseRegisterMessage(wire[HeaderSize:])
	if err != nil {
		t.Fatalf("ParseRegisterMessage: %v", err)
	}
	if !bytes.Equal(parsed.ClientID[:], id[:]) {
		t.Error("ClientID mismatch")
	}
	if parsed.Meta != nil {
		t.Error("Meta should be nil for legacy messages")
	}
}
