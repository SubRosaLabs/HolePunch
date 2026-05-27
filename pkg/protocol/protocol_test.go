package protocol

import (
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
