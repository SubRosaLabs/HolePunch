package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
		{[]byte{byte(PacketTypeIPPacket)}, true},
		{[]byte{byte(PacketTypeUDPData)}, true},
		// Reverse listener control packets
		{[]byte{byte(PacketTypeReverseBindRequest)}, true},
		{[]byte{byte(PacketTypeReverseBindAck)}, true},
		{[]byte{byte(PacketTypeReverseOpen)}, true},
		{[]byte{byte(PacketTypeReverseUnbind)}, true},
		{[]byte{0}, false},
		{[]byte{100}, false},
		{[]byte{}, false},
	}

	for _, tc := range testCases {
		got := IsProxyPacket(tc.data)
		if got != tc.expect {
			t.Errorf("IsProxyPacket(%v): got %v, want %v", tc.data, got, tc.expect)
		}
	}
}

func TestProxyPacketTypes(t *testing.T) {
	if PacketTypeTCPConnect < 20 || PacketTypeTCPConnect > 30 {
		t.Error("PacketTypeTCPConnect out of range")
	}
	if PacketTypeIPPacket != 30 {
		t.Errorf("PacketTypeIPPacket should be 30, got %d", PacketTypeIPPacket)
	}
	if PacketTypeReverseBindRequest != 40 {
		t.Errorf("PacketTypeReverseBindRequest should be 40, got %d", PacketTypeReverseBindRequest)
	}
	if PacketTypeReverseUnbind != 43 {
		t.Errorf("PacketTypeReverseUnbind should be 43, got %d", PacketTypeReverseUnbind)
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

func (c *captureConn) Read(b []byte) (int, error) { return 0, net.ErrClosed }
func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Write(b)
}
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }
func (c *captureConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte{}, c.buf.Bytes()...)
}

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

// ── EOF propagation ────────────────────────────────────────────────────────

// TestEOFForwardedToOperator verifies that when the remote server closes its
// connection (EOF), the operator receives a TCPClose so the browser's local
// connection can be torn down promptly (the "visual elements not loading" fix).
func TestEOFForwardedToOperator(t *testing.T) {
	// Set up a real TCP server that sends data then closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("hello"))
		c.Close() // graceful EOF
	}()

	var sentPkts []PacketType
	var mu sync.Mutex
	sendFunc := func(_ [32]byte, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		mu.Lock()
		sentPkts = append(sentPkts, PacketType(data[0]))
		mu.Unlock()
		return nil
	}

	m := NewManager(sendFunc)
	var peerID [32]byte

	// Create a stream whose Conn points at the test server.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	stream := &TCPStream{
		ID:      1,
		Conn:    conn,
		PeerID:  peerID,
		DstAddr: ln.Addr().String(),
		Ready:   make(chan struct{}),
	}
	m.mu.Lock()
	m.streams[1] = stream
	m.mu.Unlock()

	// readFromRemote should send TCPData then TCPClose.
	go m.readFromRemote(stream)

	<-serverDone
	// Give the goroutine time to process EOF and send the close packet.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(sentPkts) == 0 {
		t.Fatal("no packets sent")
	}
	last := sentPkts[len(sentPkts)-1]
	if last != PacketTypeTCPClose {
		t.Errorf("last packet should be TCPClose after EOF, got %d", last)
	}
}

// ── Concurrent dials don't block each other ────────────────────────────────

// TestConcurrentTCPConnect verifies that N simultaneous TCPConnect packets are
// all handled without blocking each other — the critical fix for web pages
// whose many resources previously queued behind a single slow dial.
func TestConcurrentTCPConnect(t *testing.T) {
	const N = 10

	// N echo servers, one per stream.
	addrs := make([]string, N)
	for i := 0; i < N; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		addrs[i] = ln.Addr().String()
		go func(l net.Listener) {
			c, err := l.Accept()
			if err != nil {
				return
			}
			io.Copy(c, c)
			c.Close()
		}(ln)
	}

	var acks sync.Map
	sendFunc := func(_ [32]byte, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		pkt, err := ParseProxyPacket(data)
		if err != nil {
			return nil
		}
		if pkt.Type == PacketTypeTCPConnectAck {
			acks.Store(pkt.StreamID, true)
		}
		return nil
	}

	m := NewManager(sendFunc)
	var peerID [32]byte

	start := time.Now()
	for i := 0; i < N; i++ {
		pkt := &ProxyPacket{
			Type:     PacketTypeTCPConnect,
			StreamID: uint32(i + 1),
			DstAddr:  addrs[i],
		}
		if err := m.HandlePacket(peerID, pkt.Serialize()); err != nil {
			t.Fatalf("HandlePacket[%d]: %v", i, err)
		}
	}

	// All N dials should complete well within 2s total (not N×dial_time).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		count := 0
		acks.Range(func(_, _ any) bool { count++; return true })
		if count == N {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	count := 0
	acks.Range(func(_, _ any) bool { count++; return true })
	if count != N {
		t.Errorf("got %d/%d acks in %s", count, N, time.Since(start))
	}
}

// ── Reverse listener packet round-trip ────────────────────────────────────

// TestReverseListenerPacketFlow tests the full packet exchange for a reverse
// listener: ReverseBindRequest → ReverseBindAck → ReverseOpen → TCPConnectAck.
func TestReverseListenerPacketFlow(t *testing.T) {
	// Set up a real local service the "operator" will connect to.
	localSvc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer localSvc.Close()
	svcAddr := localSvc.Addr().String()

	go func() {
		c, err := localSvc.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("svc_response"))
		c.Close()
	}()

	// Agent manager: receives ReverseBindRequest, binds a port.
	var agentSent []ProxyPacket
	var agentMu sync.Mutex
	agentSend := func(_ [32]byte, data []byte) error {
		pkt, err := ParseProxyPacket(data)
		if err != nil {
			return nil
		}
		agentMu.Lock()
		agentSent = append(agentSent, *pkt)
		agentMu.Unlock()
		return nil
	}
	agentMgr := NewManager(agentSend)
	defer agentMgr.Close()

	// Operator manager: receives ReverseBindAck and ReverseOpen, connects to svcAddr.
	var operSent []ProxyPacket
	var operMu sync.Mutex
	operSend := func(_ [32]byte, data []byte) error {
		pkt, err := ParseProxyPacket(data)
		if err != nil {
			return nil
		}
		operMu.Lock()
		operSent = append(operSent, *pkt)
		operMu.Unlock()
		return nil
	}
	operMgr := NewManager(operSend)
	defer operMgr.Close()

	var peerID [32]byte

	// Step 1: operator sends ReverseBindRequest to agent.
	bindPort := 0 // will be overwritten; for test use a free port
	ln0, _ := net.Listen("tcp", "127.0.0.1:0")
	bindPort = ln0.Addr().(*net.TCPAddr).Port
	ln0.Close()

	go func() {
		operMgr.AddReversePortForward(bindPort, svcAddr, peerID)
	}()

	// Wait for the ReverseBindRequest to be "sent" (captured in agentSend)
	time.Sleep(50 * time.Millisecond)

	// Find the ReverseBindRequest that the operator produced.
	// In a real deployment operMgr.sendFunc delivers to the agent.
	// Here we call agentMgr.HandlePacket directly.
	bindReqPkt := &ProxyPacket{
		Type:     PacketTypeReverseBindRequest,
		StreamID: uint32(bindPort),
		DstAddr:  svcAddr,
	}
	if err := agentMgr.HandlePacket(peerID, bindReqPkt.Serialize()); err != nil {
		t.Fatalf("agent HandlePacket(ReverseBindRequest): %v", err)
	}

	// Agent should emit ReverseBindAck.
	time.Sleep(100 * time.Millisecond)
	agentMu.Lock()
	var bindAck *ProxyPacket
	for i := range agentSent {
		if agentSent[i].Type == PacketTypeReverseBindAck {
			bindAck = &agentSent[i]
			break
		}
	}
	agentMu.Unlock()

	if bindAck == nil {
		t.Fatal("agent did not send ReverseBindAck")
	}
	if len(bindAck.Payload) != 0 {
		t.Fatalf("ReverseBindAck has error payload: %s", bindAck.Payload)
	}

	// Deliver ack to operator so AddReversePortForward unblocks.
	if err := operMgr.HandlePacket(peerID, bindAck.Serialize()); err != nil {
		t.Fatalf("operator HandlePacket(ReverseBindAck): %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Step 2: simulate an inbound connection to the agent's bound port.
	inbound, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", bindPort))
	if err != nil {
		t.Fatalf("dial agent bind port: %v", err)
	}
	defer inbound.Close()

	// Agent emits ReverseOpen.
	time.Sleep(200 * time.Millisecond)
	agentMu.Lock()
	var revOpen *ProxyPacket
	for i := range agentSent {
		if agentSent[i].Type == PacketTypeReverseOpen {
			revOpen = &agentSent[i]
			break
		}
	}
	agentMu.Unlock()

	if revOpen == nil {
		t.Fatal("agent did not send ReverseOpen")
	}

	// Step 3: operator handles ReverseOpen → connects to svcAddr → sends TCPConnectAck.
	if err := operMgr.HandlePacket(peerID, revOpen.Serialize()); err != nil {
		t.Fatalf("operator HandlePacket(ReverseOpen): %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	operMu.Lock()
	var ack *ProxyPacket
	for i := range operSent {
		if operSent[i].Type == PacketTypeTCPConnectAck {
			ack = &operSent[i]
			break
		}
	}
	operMu.Unlock()

	if ack == nil {
		t.Fatal("operator did not send TCPConnectAck after ReverseOpen")
	}
}

// ── Manager new-field sanity ───────────────────────────────────────────────

func TestManagerReverseFields(t *testing.T) {
	m := NewManager(func(_ [32]byte, _ []byte) error { return nil })
	if m.reverseListeners == nil {
		t.Error("reverseListeners map not initialized")
	}
	if m.reverseForwards == nil {
		t.Error("reverseForwards map not initialized")
	}
	if m.pendingBinds == nil {
		t.Error("pendingBinds map not initialized")
	}
}
