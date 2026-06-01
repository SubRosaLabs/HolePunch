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

func TestWireVersionIsTwo(t *testing.T) {
	// Sanity guard: bumping this constant is a breaking protocol change.
	if WireVersion != 2 {
		t.Errorf("WireVersion: got %d, want 2", WireVersion)
	}
}
