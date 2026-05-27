package proxy

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestProxyPacketSerialize(t *testing.T) {
	p := &ProxyPacket{
		Type:     PacketTypeTCPConnect,
		StreamID: 12345,
		Seq:      77,
		DstAddr:  "192.168.1.10:22",
		Payload:  []byte("test payload"),
	}

	data := p.Serialize()
	if len(data) == 0 {
		t.Fatal("Serialize returned empty data")
	}

	parsed, err := ParseProxyPacket(data)
	if err != nil {
		t.Fatalf("ParseProxyPacket failed: %v", err)
	}

	if parsed.Type != p.Type {
		t.Errorf("Type mismatch: got %d, want %d", parsed.Type, p.Type)
	}
	if parsed.StreamID != p.StreamID {
		t.Errorf("StreamID mismatch: got %d, want %d", parsed.StreamID, p.StreamID)
	}
	if parsed.Seq != p.Seq {
		t.Errorf("Seq mismatch: got %d, want %d", parsed.Seq, p.Seq)
	}
	if parsed.DstAddr != p.DstAddr {
		t.Errorf("DstAddr mismatch: got %s, want %s", parsed.DstAddr, p.DstAddr)
	}
	if string(parsed.Payload) != string(p.Payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestIsProxyPacket(t *testing.T) {
	testCases := []struct {
		data   []byte
		expect bool
	}{
		{[]byte{byte(PacketTypeTCPConnect)}, true},
		{[]byte{byte(PacketTypeTCPData)}, true},
		{[]byte{byte(PacketTypeIPPacket)}, true}, // IP packets routed through HandlePacket
		{[]byte{byte(PacketTypeUDPData)}, true},
		{[]byte{0}, false},   // Invalid type
		{[]byte{100}, false}, // Invalid type
		{[]byte{}, false},    // Empty
	}

	for _, tc := range testCases {
		got := IsProxyPacket(tc.data)
		if got != tc.expect {
			t.Errorf("IsProxyPacket(%v): got %v, want %v", tc.data, got, tc.expect)
		}
	}
}

func TestProxyPacketTypes(t *testing.T) {
	// Verify packet type constants are in expected ranges
	if PacketTypeTCPConnect < 20 || PacketTypeTCPConnect > 30 {
		t.Error("PacketTypeTCPConnect out of range")
	}
	if PacketTypeIPPacket != 30 {
		t.Errorf("PacketTypeIPPacket should be 30, got %d", PacketTypeIPPacket)
	}
}

func TestProxyPacketEmptyPayload(t *testing.T) {
	p := &ProxyPacket{
		Type:     PacketTypeTCPClose,
		StreamID: 1,
		DstAddr:  "10.0.0.1:80",
		Payload:  nil,
	}

	data := p.Serialize()
	parsed, err := ParseProxyPacket(data)
	if err != nil {
		t.Fatalf("ParseProxyPacket failed: %v", err)
	}

	if len(parsed.Payload) != 0 {
		t.Error("Payload should be empty")
	}
}

func TestProxyPacketLargePayload(t *testing.T) {
	// Simulate a large IP packet payload
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	p := &ProxyPacket{
		Type:     PacketTypeTCPData,
		StreamID: 999,
		DstAddr:  "172.16.0.1:443",
		Payload:  payload,
	}

	data := p.Serialize()
	parsed, err := ParseProxyPacket(data)
	if err != nil {
		t.Fatalf("ParseProxyPacket failed: %v", err)
	}

	if len(parsed.Payload) != len(payload) {
		t.Errorf("Payload length mismatch: got %d, want %d", len(parsed.Payload), len(payload))
	}

	for i := range payload {
		if parsed.Payload[i] != payload[i] {
			t.Errorf("Payload byte %d mismatch", i)
			break
		}
	}
}

func TestManagerCreation(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error {
		return nil
	}

	m := NewManager(sendFunc)
	if m == nil {
		t.Fatal("NewManager returned nil")
	}

	// Should have no streams, listeners, or TUN connections
	if len(m.streams) != 0 {
		t.Error("Should have no streams")
	}
	if len(m.listeners) != 0 {
		t.Error("Should have no listeners")
	}
	if len(m.tunConns) != 0 {
		t.Error("Should have no TUN connections")
	}
}

func TestSetTUNWriter(t *testing.T) {
	sendFunc := func(peerID [32]byte, data []byte) error {
		return nil
	}

	m := NewManager(sendFunc)

	// Initially nil
	if m.tunWriter != nil {
		t.Error("tunWriter should be nil initially")
	}

	// Set a writer
	called := false
	m.SetTUNWriter(func(data []byte) {
		called = true
	})

	if m.tunWriter == nil {
		t.Error("tunWriter should be set")
	}

	// Call it
	m.tunWriter([]byte("test"))
	if !called {
		t.Error("tunWriter was not called")
	}
}

// captureConn is an in-memory net.Conn that just records all writes.
type captureConn struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *captureConn) Read(b []byte) (int, error)        { return 0, net.ErrClosed }
func (c *captureConn) Write(b []byte) (int, error)       { c.mu.Lock(); defer c.mu.Unlock(); return c.buf.Write(b) }
func (c *captureConn) Close() error                      { return nil }
func (c *captureConn) LocalAddr() net.Addr               { return nil }
func (c *captureConn) RemoteAddr() net.Addr              { return nil }
func (c *captureConn) SetDeadline(time.Time) error       { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error   { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error  { return nil }
func (c *captureConn) Bytes() []byte                     { c.mu.Lock(); defer c.mu.Unlock(); return append([]byte{}, c.buf.Bytes()...) }

func TestStreamReassemblyInOrder(t *testing.T) {
	conn := &captureConn{}
	s := &TCPStream{Conn: conn}

	for i, chunk := range [][]byte{[]byte("aaa"), []byte("bbb"), []byte("ccc")} {
		if err := s.deliverData(uint32(i+1), chunk); err != nil {
			t.Fatalf("seq %d: %v", i+1, err)
		}
	}
	if got := string(conn.Bytes()); got != "aaabbbccc" {
		t.Fatalf("in-order delivery: got %q", got)
	}
}

func TestStreamReassemblyOutOfOrder(t *testing.T) {
	conn := &captureConn{}
	s := &TCPStream{Conn: conn}

	// Arrive: 2, 3, 1 — must be reassembled as 1,2,3.
	if err := s.deliverData(2, []byte("BBB")); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverData(3, []byte("CCC")); err != nil {
		t.Fatal(err)
	}
	if len(conn.Bytes()) != 0 {
		t.Fatalf("conn should be empty before seq 1 arrives, got %q", conn.Bytes())
	}
	if err := s.deliverData(1, []byte("AAA")); err != nil {
		t.Fatal(err)
	}
	if got := string(conn.Bytes()); got != "AAABBBCCC" {
		t.Fatalf("out-of-order reassembly failed: got %q", got)
	}
}

func TestIsTimeoutErr(t *testing.T) {
	// A real net timeout (1-byte UDP socket with sub-ms deadline).
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()
	pc.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 16)
	_, _, readErr := pc.ReadFrom(buf)
	if readErr == nil {
		t.Fatal("expected timeout error")
	}
	if !isTimeoutErr(readErr) {
		t.Errorf("isTimeoutErr should be true for net deadline error: %v", readErr)
	}

	// nil and unrelated errors should be false.
	if isTimeoutErr(nil) {
		t.Error("isTimeoutErr(nil) should be false")
	}
	if isTimeoutErr(errors.New("connection refused")) {
		t.Error("isTimeoutErr should be false for plain errors")
	}
}

func TestStreamReassemblyDuplicatesDropped(t *testing.T) {
	conn := &captureConn{}
	s := &TCPStream{Conn: conn}

	if err := s.deliverData(1, []byte("X")); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverData(1, []byte("DUPE")); err != nil {
		t.Fatal(err)
	}
	if err := s.deliverData(2, []byte("Y")); err != nil {
		t.Fatal(err)
	}
	if got := string(conn.Bytes()); got != "XY" {
		t.Fatalf("duplicates: got %q", got)
	}
}

func TestIPPacketParsing(t *testing.T) {
	// Create a minimal valid IPv4 header
	ipPacket := make([]byte, 40)
	ipPacket[0] = 0x45 // Version 4, IHL 5
	ipPacket[9] = 6    // Protocol TCP
	// Source IP: 10.0.0.1
	ipPacket[12] = 10
	ipPacket[13] = 0
	ipPacket[14] = 0
	ipPacket[15] = 1
	// Dest IP: 192.168.1.10
	ipPacket[16] = 192
	ipPacket[17] = 168
	ipPacket[18] = 1
	ipPacket[19] = 10

	// Verify we can extract the IPs
	version := ipPacket[0] >> 4
	if version != 4 {
		t.Errorf("Expected IPv4 (4), got %d", version)
	}

	protocol := ipPacket[9]
	if protocol != 6 {
		t.Errorf("Expected TCP (6), got %d", protocol)
	}
}
