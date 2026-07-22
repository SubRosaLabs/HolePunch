// Package proxy provides userspace TCP/UDP forwarding without requiring root
package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// PacketType identifies proxy packet types
type PacketType uint8

const (
	PacketTypeTCPConnect    PacketType = 20 // Request TCP connection
	PacketTypeTCPConnectAck PacketType = 21 // TCP connection established
	PacketTypeTCPData       PacketType = 22 // TCP data
	PacketTypeTCPClose      PacketType = 23 // TCP connection closed
	PacketTypeTCPError      PacketType = 24 // TCP connection error
	PacketTypeUDPData       PacketType = 25 // UDP datagram
	PacketTypeIPPacket      PacketType = 30 // Raw IP packet for TUN mode

	// Reverse listener: operator asks agent to bind a port; inbound connections
	// are reverse-proxied back through the tunnel to the operator's local dest.
	PacketTypeReverseBindRequest PacketType = 40 // Operator→Agent: bind port, StreamID=bindPort, DstAddr=operatorDest
	PacketTypeReverseBindAck     PacketType = 41 // Agent→Operator: ack/error, StreamID=bindPort, Payload=err or empty
	PacketTypeReverseOpen        PacketType = 42 // Agent→Operator: inbound arrived, StreamID=streamID, DstAddr=operatorDest
	PacketTypeReverseUnbind      PacketType = 43 // Operator→Agent: stop listening, StreamID=bindPort
)

// ProxyPacket represents a proxy protocol packet.
// Seq is a per-stream-direction sequence number used to reassemble TCPData
// packets in order on the receiver (UDP transport may reorder packets).
type ProxyPacket struct {
	Type     PacketType
	StreamID uint32 // Unique stream identifier
	Seq      uint32 // Per-stream-direction sequence (TCPData only)
	DstAddr  string // Destination address (ip:port)
	Payload  []byte
}

// Serialize serializes a proxy packet
// Wire format: type(1) + streamID(4) + seq(4) + addrLen(2) + addr + payloadLen(4) + payload
func (p *ProxyPacket) Serialize() []byte {
	addrBytes := []byte(p.DstAddr)
	buf := make([]byte, 0, 15+len(addrBytes)+len(p.Payload))
	buf = append(buf, byte(p.Type))

	scratch := make([]byte, 4)
	binary.BigEndian.PutUint32(scratch, p.StreamID)
	buf = append(buf, scratch...)

	binary.BigEndian.PutUint32(scratch, p.Seq)
	buf = append(buf, scratch...)

	addrLen := make([]byte, 2)
	binary.BigEndian.PutUint16(addrLen, uint16(len(addrBytes)))
	buf = append(buf, addrLen...)
	buf = append(buf, addrBytes...)

	binary.BigEndian.PutUint32(scratch, uint32(len(p.Payload)))
	buf = append(buf, scratch...)
	buf = append(buf, p.Payload...)

	return buf
}

// ParseProxyPacket parses a proxy packet from bytes
func ParseProxyPacket(data []byte) (*ProxyPacket, error) {
	// 1 (type) + 4 (streamID) + 4 (seq) + 2 (addrLen) + 4 (payloadLen) = 15 byte header
	if len(data) < 15 {
		return nil, fmt.Errorf("packet too short")
	}

	p := &ProxyPacket{Type: PacketType(data[0])}
	p.StreamID = binary.BigEndian.Uint32(data[1:5])
	p.Seq = binary.BigEndian.Uint32(data[5:9])

	addrLen := binary.BigEndian.Uint16(data[9:11])
	if len(data) < 11+int(addrLen)+4 {
		return nil, fmt.Errorf("packet truncated")
	}
	p.DstAddr = string(data[11 : 11+addrLen])

	offset := 11 + int(addrLen)
	payloadLen := binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	if len(data) < offset+int(payloadLen) {
		return nil, fmt.Errorf("payload truncated")
	}
	p.Payload = data[offset : offset+int(payloadLen)]

	return p, nil
}

// IsProxyPacket checks if data is a proxy packet (TCP/UDP stream, raw IP, or reverse listener control)
func IsProxyPacket(data []byte) bool {
	if len(data) < 1 {
		return false
	}
	pktType := PacketType(data[0])
	if pktType >= PacketTypeTCPConnect && pktType <= PacketTypeUDPData {
		return true
	}
	if pktType == PacketTypeIPPacket {
		return true
	}
	return pktType >= PacketTypeReverseBindRequest && pktType <= PacketTypeReverseUnbind
}

// TCPStream represents an active TCP stream.
//
// To keep the application-level TCP byte stream intact over UDP transport,
// each direction maintains its own monotonically increasing Seq:
//
//	sendSeq:   next outbound seq to stamp (incremented per TCPData packet sent)
//	recvSeq:   next inbound seq we expect to write to Conn
//	recvBuf:   out-of-order packets, keyed by Seq, drained when recvSeq advances
//	maxBuffered: cap to bound memory in case of persistent loss
type TCPStream struct {
	ID      uint32
	Conn    net.Conn
	PeerID  [32]byte
	DstAddr string
	Ready   chan struct{} // Signals connection is ready
	Error   error
	closed  bool
	mu      sync.Mutex

	sendSeq uint32
	recvSeq uint32
	recvBuf map[uint32][]byte
}

const tcpStreamReorderBufferLimit = 256

// nextSendSeq returns the next outbound seq for this stream (1-indexed).
func (s *TCPStream) nextSendSeq() uint32 {
	s.mu.Lock()
	s.sendSeq++
	seq := s.sendSeq
	s.mu.Unlock()
	return seq
}

// deliverData writes payload to s.Conn in seq order, buffering out-of-order
// packets up to tcpStreamReorderBufferLimit. Returns first error encountered.
func (s *TCPStream) deliverData(seq uint32, payload []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	if s.recvBuf == nil {
		s.recvBuf = make(map[uint32][]byte)
	}
	// Initial expected seq is 1 (sender starts at 1 via nextSendSeq).
	expected := s.recvSeq + 1

	if seq < expected {
		// Duplicate / stale; already written or pre-handshake. Drop.
		s.mu.Unlock()
		return nil
	}

	if seq > expected {
		// Out of order — buffer and wait.
		if len(s.recvBuf) >= tcpStreamReorderBufferLimit {
			// Don't grow unboundedly. Drop oldest by selecting the
			// largest gap; simplest is to just drop this one.
			s.mu.Unlock()
			return nil
		}
		// Copy payload — the caller's buf may be reused.
		cp := make([]byte, len(payload))
		copy(cp, payload)
		s.recvBuf[seq] = cp
		s.mu.Unlock()
		return nil
	}

	// In-order. Write this one and drain consecutive buffered packets.
	conn := s.Conn
	pending := [][]byte{payload}
	s.recvSeq = seq
	for {
		next := s.recvSeq + 1
		buffered, ok := s.recvBuf[next]
		if !ok {
			break
		}
		delete(s.recvBuf, next)
		pending = append(pending, buffered)
		s.recvSeq = next
	}
	s.mu.Unlock()

	for _, chunk := range pending {
		if _, err := conn.Write(chunk); err != nil {
			return err
		}
	}
	return nil
}

// TUNConn represents a TCP connection initiated from a TUN IP packet
type TUNConn struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Conn     net.Conn
	SeqNum   uint32 // Our sequence number
	AckNum   uint32 // Their sequence number
	State    int    // TCP state
	PeerID   [32]byte
	LastSeen time.Time
	mu       sync.Mutex
}

// Dial timeouts. TUN-mode dials are kept short so port scans don't hang
// a few seconds per scanned port; SOCKS5/port-forward dials get a longer
// budget since they're explicit user-initiated connections.
const (
	tunDialTimeout    = 3 * time.Second
	streamDialTimeout = 8 * time.Second
)

// TCP states
const (
	TCPStateClosed     = iota
	TCPStateConnecting // dial in progress; no SYN-ACK sent yet
	TCPStateSynReceived
	TCPStateEstablished
	TCPStateFinWait
)

// Manager handles proxy functionality
type Manager struct {
	sendFunc  func(peerID [32]byte, data []byte) error
	streams   map[uint32]*TCPStream
	listeners map[int]*PortForward
	socks5    *SOCKS5Server
	streamID  uint32
	tunConns  map[string]*TUNConn // key: "srcIP:srcPort-dstIP:dstPort"
	tunWriter func([]byte)        // Function to write packets back to TUN

	// Reverse listener state
	reverseListeners map[int]*ReverseListener    // agent side: active bound ports
	reverseForwards  map[int]*ReversePortForward // operator side: tracking for list/del
	pendingBinds     map[int]chan error           // operator side: waiting for ReverseBindAck

	mu sync.RWMutex
}

// PortForward represents a local port forwarding rule
type PortForward struct {
	LocalPort  int
	RemoteAddr string // Remote address (ip:port)
	PeerID     [32]byte
	listener   net.Listener
	manager    *Manager
	running    atomic.Bool
}

// ReverseListener is the agent-side binding created by a ReverseBindRequest.
// It listens on 0.0.0.0:BindPort and for each inbound connection sends a
// ReverseOpen to the operator, which then connects to DestAddr locally.
type ReverseListener struct {
	BindPort int
	DestAddr string   // operator-local address to connect to on each inbound
	PeerID   [32]byte // operator peer to notify
	listener net.Listener
	manager  *Manager
	running  atomic.Bool
}

// ReversePortForward is the operator-side record of an outstanding reverse
// listener request. Stored for listing; the actual per-connection handling
// is driven by inbound ReverseOpen packets.
type ReversePortForward struct {
	BindPort int
	DestAddr string   // operator-local address
	PeerID   [32]byte // agent peer
}

// NewManager creates a new proxy manager
func NewManager(sendFunc func(peerID [32]byte, data []byte) error) *Manager {
	return &Manager{
		sendFunc:         sendFunc,
		streams:          make(map[uint32]*TCPStream),
		listeners:        make(map[int]*PortForward),
		tunConns:         make(map[string]*TUNConn),
		reverseListeners: make(map[int]*ReverseListener),
		reverseForwards:  make(map[int]*ReversePortForward),
		pendingBinds:     make(map[int]chan error),
	}
}

// SetTUNWriter sets the function to write packets back to TUN interface
func (m *Manager) SetTUNWriter(writer func([]byte)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunWriter = writer
}

// nextStreamID generates a unique stream ID
func (m *Manager) nextStreamID() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamID++
	return m.streamID
}

// AddPortForward creates a local port forward to a remote address via a peer
func (m *Manager) AddPortForward(localPort int, remoteAddr string, peerID [32]byte) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", localPort, err)
	}

	pf := &PortForward{
		LocalPort:  localPort,
		RemoteAddr: remoteAddr,
		PeerID:     peerID,
		listener:   listener,
		manager:    m,
	}
	pf.running.Store(true)

	m.mu.Lock()
	m.listeners[localPort] = pf
	m.mu.Unlock()

	go pf.acceptLoop()

	log.Printf("Port forward: localhost:%d -> %s via peer", localPort, remoteAddr)
	return nil
}

// RemovePortForward removes a port forwarding rule
func (m *Manager) RemovePortForward(localPort int) {
	m.mu.Lock()
	pf, ok := m.listeners[localPort]
	if ok {
		delete(m.listeners, localPort)
	}
	m.mu.Unlock()

	if ok && pf != nil {
		pf.running.Store(false)
		pf.listener.Close()
	}
}

// ListPortForwards returns all active port forwards
func (m *Manager) ListPortForwards() []*PortForward {
	m.mu.RLock()
	defer m.mu.RUnlock()

	forwards := make([]*PortForward, 0, len(m.listeners))
	for _, pf := range m.listeners {
		forwards = append(forwards, pf)
	}
	return forwards
}

func (pf *PortForward) acceptLoop() {
	for pf.running.Load() {
		conn, err := pf.listener.Accept()
		if err != nil {
			if pf.running.Load() {
				log.Printf("Accept error: %v", err)
			}
			continue
		}

		go pf.handleConnection(conn)
	}
}

func (pf *PortForward) handleConnection(conn net.Conn) {
	streamID := pf.manager.nextStreamID()

	stream := &TCPStream{
		ID:      streamID,
		Conn:    conn,
		PeerID:  pf.PeerID,
		DstAddr: pf.RemoteAddr,
		Ready:   make(chan struct{}),
	}

	pf.manager.mu.Lock()
	pf.manager.streams[streamID] = stream
	pf.manager.mu.Unlock()

	// Send connect request to peer
	packet := &ProxyPacket{
		Type:     PacketTypeTCPConnect,
		StreamID: streamID,
		DstAddr:  pf.RemoteAddr,
	}

	if err := pf.manager.sendFunc(pf.PeerID, packet.Serialize()); err != nil {
		log.Printf("Failed to send connect request: %v", err)
		conn.Close()
		pf.manager.removeStream(streamID)
		return
	}

	// Wait for connection ack or error
	select {
	case <-stream.Ready:
		if stream.Error != nil {
			log.Printf("Connection failed: %v", stream.Error)
			conn.Close()
			pf.manager.removeStream(streamID)
			return
		}
	case <-time.After(10 * time.Second):
		log.Printf("Connection timeout")
		conn.Close()
		pf.manager.removeStream(streamID)
		return
	}

	// Start reading from local connection
	go pf.manager.readFromLocal(stream)
}

func (m *Manager) readFromLocal(stream *TCPStream) {
	// Cap per-packet payload so encryption overhead + UDP framing stays
	// well under common MTUs; smaller packets also reduce reorder windows.
	buf := make([]byte, 1200)

	for {
		stream.mu.Lock()
		if stream.closed {
			stream.mu.Unlock()
			return
		}
		stream.mu.Unlock()

		n, readErr := stream.Conn.Read(buf)

		// Send any data first — Read may return (n, io.EOF) for the last chunk.
		if n > 0 {
			packet := &ProxyPacket{
				Type:     PacketTypeTCPData,
				StreamID: stream.ID,
				Seq:      stream.nextSendSeq(),
				DstAddr:  stream.DstAddr,
				Payload:  buf[:n],
			}
			if err := m.sendFunc(stream.PeerID, packet.Serialize()); err != nil {
				log.Printf("Failed to send data: %v", err)
				m.closeStream(stream.ID)
				return
			}
		}

		if readErr != nil {
			// Always forward close (EOF = graceful FIN; other = error).
			pkt := &ProxyPacket{
				Type:     PacketTypeTCPClose,
				StreamID: stream.ID,
				DstAddr:  stream.DstAddr,
			}
			m.sendFunc(stream.PeerID, pkt.Serialize())
			m.closeStream(stream.ID)
			return
		}
	}
}

func (m *Manager) removeStream(streamID uint32) {
	m.mu.Lock()
	delete(m.streams, streamID)
	m.mu.Unlock()
}

func (m *Manager) closeStream(streamID uint32) {
	m.mu.Lock()
	stream, ok := m.streams[streamID]
	if ok {
		delete(m.streams, streamID)
	}
	m.mu.Unlock()

	if ok && stream != nil {
		stream.mu.Lock()
		stream.closed = true
		stream.Conn.Close()
		stream.mu.Unlock()
	}
}

// HandlePacket processes incoming proxy packets from a peer
func (m *Manager) HandlePacket(peerID [32]byte, data []byte) error {
	// Check if this is an IP packet (starts with type 30)
	if len(data) > 0 && PacketType(data[0]) == PacketTypeIPPacket {
		return m.handleIPPacket(peerID, data[1:])
	}

	packet, err := ParseProxyPacket(data)
	if err != nil {
		return err
	}

	switch packet.Type {
	case PacketTypeTCPConnect:
		return m.handleTCPConnect(peerID, packet)
	case PacketTypeTCPConnectAck:
		return m.handleTCPConnectAck(packet)
	case PacketTypeTCPData:
		return m.handleTCPData(packet)
	case PacketTypeTCPClose:
		return m.handleTCPClose(packet)
	case PacketTypeTCPError:
		return m.handleTCPError(packet)
	case PacketTypeReverseBindRequest:
		return m.handleReverseBindRequest(peerID, packet)
	case PacketTypeReverseBindAck:
		return m.handleReverseBindAck(packet)
	case PacketTypeReverseOpen:
		return m.handleReverseOpen(peerID, packet)
	case PacketTypeReverseUnbind:
		return m.handleReverseUnbind(packet)
	}

	return nil
}

func (m *Manager) handleTCPConnect(peerID [32]byte, packet *ProxyPacket) error {
	log.Printf("TCP connect request: stream %d -> %s", packet.StreamID, packet.DstAddr)

	// Guard against duplicate connect requests for the same stream ID before
	// the first dial completes.
	m.mu.Lock()
	if _, exists := m.streams[packet.StreamID]; exists {
		m.mu.Unlock()
		return nil
	}
	// Reserve the slot with a placeholder so concurrent packets don't double-dial.
	m.streams[packet.StreamID] = nil
	m.mu.Unlock()

	// Dial on a goroutine so we don't block the receive loop (and stall all
	// other streams) for up to streamDialTimeout on every new connection.
	streamID := packet.StreamID
	dstAddr := packet.DstAddr
	go func() {
		conn, err := net.DialTimeout("tcp", dstAddr, streamDialTimeout)
		if err != nil {
			log.Printf("TCP connect failed: %s: %v", dstAddr, err)
			m.mu.Lock()
			delete(m.streams, streamID)
			m.mu.Unlock()
			errPacket := &ProxyPacket{
				Type:     PacketTypeTCPError,
				StreamID: streamID,
				DstAddr:  dstAddr,
				Payload:  []byte(err.Error()),
			}
			m.sendFunc(peerID, errPacket.Serialize())
			return
		}

		stream := &TCPStream{
			ID:      streamID,
			Conn:    conn,
			PeerID:  peerID,
			DstAddr: dstAddr,
			Ready:   make(chan struct{}),
		}

		m.mu.Lock()
		m.streams[streamID] = stream
		m.mu.Unlock()

		ackPacket := &ProxyPacket{
			Type:     PacketTypeTCPConnectAck,
			StreamID: streamID,
			DstAddr:  dstAddr,
		}
		if err := m.sendFunc(peerID, ackPacket.Serialize()); err != nil {
			conn.Close()
			m.removeStream(streamID)
			return
		}

		log.Printf("TCP tunnel: connected to %s (stream %d)", dstAddr, streamID)
		go m.readFromRemote(stream)
	}()

	return nil
}

func (m *Manager) readFromRemote(stream *TCPStream) {
	buf := make([]byte, 1200)

	for {
		stream.mu.Lock()
		if stream.closed {
			stream.mu.Unlock()
			return
		}
		stream.mu.Unlock()

		n, readErr := stream.Conn.Read(buf)

		// Send data before checking the error — Read may return (n, io.EOF).
		if n > 0 {
			packet := &ProxyPacket{
				Type:     PacketTypeTCPData,
				StreamID: stream.ID,
				Seq:      stream.nextSendSeq(),
				DstAddr:  stream.DstAddr,
				Payload:  buf[:n],
			}
			if err := m.sendFunc(stream.PeerID, packet.Serialize()); err != nil {
				m.closeStream(stream.ID)
				return
			}
		}

		if readErr != nil {
			pkt := &ProxyPacket{
				Type:     PacketTypeTCPClose,
				StreamID: stream.ID,
				DstAddr:  stream.DstAddr,
			}
			m.sendFunc(stream.PeerID, pkt.Serialize())
			m.closeStream(stream.ID)
			return
		}
	}
}

func (m *Manager) handleTCPConnectAck(packet *ProxyPacket) error {
	m.mu.RLock()
	stream, ok := m.streams[packet.StreamID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown stream: %d", packet.StreamID)
	}

	// Signal that connection is ready
	select {
	case <-stream.Ready:
		// Already signaled
	default:
		close(stream.Ready)
	}

	log.Printf("TCP tunnel established: stream %d -> %s", stream.ID, stream.DstAddr)
	return nil
}

func (m *Manager) handleTCPData(packet *ProxyPacket) error {
	m.mu.RLock()
	stream, ok := m.streams[packet.StreamID]
	m.mu.RUnlock()

	if !ok {
		return nil // Stream may have been closed
	}

	// deliverData handles closed-check, in-order write, and reorder buffering.
	return stream.deliverData(packet.Seq, packet.Payload)
}

func (m *Manager) handleTCPClose(packet *ProxyPacket) error {
	m.closeStream(packet.StreamID)
	return nil
}

func (m *Manager) handleTCPError(packet *ProxyPacket) error {
	m.mu.RLock()
	stream, ok := m.streams[packet.StreamID]
	m.mu.RUnlock()

	if ok {
		stream.Error = fmt.Errorf("%s", string(packet.Payload))
		select {
		case <-stream.Ready:
		default:
			close(stream.Ready)
		}
	}

	log.Printf("TCP error for stream %d: %s", packet.StreamID, string(packet.Payload))
	m.closeStream(packet.StreamID)
	return nil
}

// SOCKS5Server provides a SOCKS5 proxy interface
type SOCKS5Server struct {
	listener net.Listener
	manager  *Manager
	peerID   [32]byte
	running  atomic.Bool
	port     int
}

// StartSOCKS5 starts a SOCKS5 server on the given port
func (m *Manager) StartSOCKS5(port int, peerID [32]byte) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}

	m.socks5 = &SOCKS5Server{
		listener: listener,
		manager:  m,
		peerID:   peerID,
		port:     port,
	}
	m.socks5.running.Store(true)

	go m.socks5.acceptLoop()

	log.Printf("SOCKS5 proxy started on 127.0.0.1:%d", port)
	return nil
}

// StopSOCKS5 stops the SOCKS5 server
func (m *Manager) StopSOCKS5() {
	if m.socks5 != nil {
		m.socks5.running.Store(false)
		m.socks5.listener.Close()
		m.socks5 = nil
	}
}

// GetSOCKS5Port returns the SOCKS5 port if running
func (m *Manager) GetSOCKS5Port() int {
	if m.socks5 != nil {
		return m.socks5.port
	}
	return 0
}

func (s *SOCKS5Server) acceptLoop() {
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.Printf("SOCKS5 accept error: %v", err)
			}
			continue
		}

		go s.handleClient(conn)
	}
}

// readFull reads exactly n bytes from r, returning an error on short read.
func readFull(r io.Reader, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

func (s *SOCKS5Server) handleClient(conn net.Conn) {
	defer func() {
		// conn.Close() is called explicitly on error paths; this catches panics.
		if r := recover(); r != nil {
			conn.Close()
		}
	}()

	// ── Greeting ────────────────────────────────────────────────────────────
	// VER(1) + NMETHODS(1)
	hdr, err := readFull(conn, 2)
	if err != nil || hdr[0] != 0x05 {
		conn.Close()
		return
	}
	nMethods := int(hdr[1])
	if nMethods > 0 {
		if _, err := readFull(conn, nMethods); err != nil {
			conn.Close()
			return
		}
	}
	// No auth required
	conn.Write([]byte{0x05, 0x00})

	// ── Request ──────────────────────────────────────────────────────────────
	// VER(1) + CMD(1) + RSV(1) + ATYP(1)
	req, err := readFull(conn, 4)
	if err != nil {
		conn.Close()
		return
	}
	if req[0] != 0x05 || req[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	}

	var dstAddr string

	switch req[3] {
	case 0x01: // IPv4
		addr, err := readFull(conn, 4+2)
		if err != nil {
			conn.Close()
			return
		}
		ip := net.IP(addr[:4])
		port := binary.BigEndian.Uint16(addr[4:6])
		dstAddr = fmt.Sprintf("%s:%d", ip.String(), port)

	case 0x03: // Domain
		lenBuf, err := readFull(conn, 1)
		if err != nil {
			conn.Close()
			return
		}
		domainLen := int(lenBuf[0])
		rest, err := readFull(conn, domainLen+2)
		if err != nil {
			conn.Close()
			return
		}
		domain := string(rest[:domainLen])
		port := binary.BigEndian.Uint16(rest[domainLen : domainLen+2])
		dstAddr = fmt.Sprintf("%s:%d", domain, port)

	case 0x04: // IPv6
		addr, err := readFull(conn, 16+2)
		if err != nil {
			conn.Close()
			return
		}
		ip := net.IP(addr[:16])
		port := binary.BigEndian.Uint16(addr[16:18])
		dstAddr = fmt.Sprintf("[%s]:%d", ip.String(), port)

	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		return
	}

	// Create stream and forward
	streamID := s.manager.nextStreamID()
	log.Printf("SOCKS5: stream %d connecting to %s", streamID, dstAddr)

	stream := &TCPStream{
		ID:      streamID,
		Conn:    conn,
		PeerID:  s.peerID,
		DstAddr: dstAddr,
		Ready:   make(chan struct{}),
	}

	s.manager.mu.Lock()
	s.manager.streams[streamID] = stream
	s.manager.mu.Unlock()

	// Send connect request to peer
	packet := &ProxyPacket{
		Type:     PacketTypeTCPConnect,
		StreamID: streamID,
		DstAddr:  dstAddr,
	}

	if err := s.manager.sendFunc(s.peerID, packet.Serialize()); err != nil {
		log.Printf("SOCKS5: failed to send connect request: %v", err)
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		s.manager.removeStream(streamID)
		return
	}

	// Wait for connection ack or error
	select {
	case <-stream.Ready:
		if stream.Error != nil {
			log.Printf("SOCKS5: stream %d error: %v", streamID, stream.Error)
			conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			conn.Close()
			s.manager.removeStream(streamID)
			return
		}
	case <-time.After(10 * time.Second):
		log.Printf("SOCKS5: stream %d timeout waiting for connection", streamID)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		conn.Close()
		s.manager.removeStream(streamID)
		return
	}

	log.Printf("SOCKS5: stream %d connected to %s", streamID, dstAddr)
	// Send success response
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00})

	// Start reading from local connection (blocking)
	s.manager.readFromLocal(stream)
}

// Close cleans up all resources
func (m *Manager) Close() {
	m.StopSOCKS5()

	m.mu.Lock()
	for port, pf := range m.listeners {
		pf.running.Store(false)
		pf.listener.Close()
		delete(m.listeners, port)
	}

	for id, stream := range m.streams {
		if stream != nil {
			stream.mu.Lock()
			stream.closed = true
			if stream.Conn != nil {
				stream.Conn.Close()
			}
			stream.mu.Unlock()
		}
		delete(m.streams, id)
	}

	for key, tc := range m.tunConns {
		if tc.Conn != nil {
			tc.Conn.Close()
		}
		delete(m.tunConns, key)
	}

	for port, rl := range m.reverseListeners {
		rl.running.Store(false)
		rl.listener.Close()
		delete(m.reverseListeners, port)
	}
	m.mu.Unlock()
}

// ── Reverse listener: operator-side API ────────────────────────────────────

// AddReversePortForward sends a ReverseBindRequest to the agent and blocks
// until the agent confirms the port is bound (or returns an error/timeout).
func (m *Manager) AddReversePortForward(bindPort int, destAddr string, peerID [32]byte) error {
	done := make(chan error, 1)

	m.mu.Lock()
	if _, exists := m.reverseForwards[bindPort]; exists {
		m.mu.Unlock()
		return fmt.Errorf("reverse listener on port %d already exists", bindPort)
	}
	m.pendingBinds[bindPort] = done
	m.reverseForwards[bindPort] = &ReversePortForward{
		BindPort: bindPort,
		DestAddr: destAddr,
		PeerID:   peerID,
	}
	m.mu.Unlock()

	pkt := &ProxyPacket{
		Type:     PacketTypeReverseBindRequest,
		StreamID: uint32(bindPort),
		DstAddr:  destAddr,
	}
	if err := m.sendFunc(peerID, pkt.Serialize()); err != nil {
		m.mu.Lock()
		delete(m.pendingBinds, bindPort)
		delete(m.reverseForwards, bindPort)
		m.mu.Unlock()
		return err
	}

	select {
	case err := <-done:
		if err != nil {
			m.mu.Lock()
			delete(m.reverseForwards, bindPort)
			m.mu.Unlock()
			return err
		}
		return nil
	case <-time.After(10 * time.Second):
		m.mu.Lock()
		delete(m.pendingBinds, bindPort)
		delete(m.reverseForwards, bindPort)
		m.mu.Unlock()
		return fmt.Errorf("timeout waiting for agent to bind port %d", bindPort)
	}
}

// RemoveReversePortForward tells the agent to stop its reverse listener.
func (m *Manager) RemoveReversePortForward(bindPort int) error {
	m.mu.Lock()
	pf, ok := m.reverseForwards[bindPort]
	if ok {
		delete(m.reverseForwards, bindPort)
	}
	m.mu.Unlock()

	if !ok {
		return fmt.Errorf("no reverse listener on port %d", bindPort)
	}

	pkt := &ProxyPacket{
		Type:     PacketTypeReverseUnbind,
		StreamID: uint32(bindPort),
	}
	return m.sendFunc(pf.PeerID, pkt.Serialize())
}

// ListReversePortForwards returns active reverse port forwards (operator side).
func (m *Manager) ListReversePortForwards() []*ReversePortForward {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*ReversePortForward, 0, len(m.reverseForwards))
	for _, pf := range m.reverseForwards {
		out = append(out, pf)
	}
	return out
}

// handleReverseBindAck is called on the operator when the agent confirms (or
// rejects) the bind request.
func (m *Manager) handleReverseBindAck(packet *ProxyPacket) error {
	bindPort := int(packet.StreamID)

	m.mu.Lock()
	done, ok := m.pendingBinds[bindPort]
	if ok {
		delete(m.pendingBinds, bindPort)
	}
	m.mu.Unlock()

	if !ok {
		return nil
	}

	if len(packet.Payload) > 0 {
		done <- fmt.Errorf("%s", string(packet.Payload))
	} else {
		done <- nil
	}
	return nil
}

// handleReverseOpen is called on the operator when the agent has received an
// inbound connection and wants the operator to connect to its local destAddr.
// Dial runs on a goroutine to avoid blocking the receive loop.
func (m *Manager) handleReverseOpen(peerID [32]byte, packet *ProxyPacket) error {
	log.Printf("Reverse open: stream %d, connecting to %s", packet.StreamID, packet.DstAddr)
	streamID := packet.StreamID
	dstAddr := packet.DstAddr
	go func() {
		conn, err := net.DialTimeout("tcp", dstAddr, streamDialTimeout)
		if err != nil {
			log.Printf("Reverse open: dial %s failed: %v", dstAddr, err)
			errPkt := &ProxyPacket{
				Type:     PacketTypeTCPError,
				StreamID: streamID,
				DstAddr:  dstAddr,
				Payload:  []byte(err.Error()),
			}
			m.sendFunc(peerID, errPkt.Serialize())
			return
		}

		stream := &TCPStream{
			ID:      streamID,
			Conn:    conn,
			PeerID:  peerID,
			DstAddr: dstAddr,
			Ready:   make(chan struct{}),
		}

		m.mu.Lock()
		m.streams[streamID] = stream
		m.mu.Unlock()

		ack := &ProxyPacket{
			Type:     PacketTypeTCPConnectAck,
			StreamID: streamID,
			DstAddr:  dstAddr,
		}
		if err := m.sendFunc(peerID, ack.Serialize()); err != nil {
			conn.Close()
			m.removeStream(streamID)
			return
		}

		log.Printf("Reverse tunnel: connected to %s (stream %d)", dstAddr, streamID)
		go m.readFromRemote(stream)
	}()
	return nil
}

// ── Reverse listener: agent-side ──────────────────────────────────────────

// handleReverseBindRequest is called on the agent when the operator asks it
// to bind a port and reverse-proxy inbound connections.
func (m *Manager) handleReverseBindRequest(peerID [32]byte, packet *ProxyPacket) error {
	bindPort := int(packet.StreamID)
	destAddr := packet.DstAddr

	if err := m.addReverseListener(bindPort, destAddr, peerID); err != nil {
		ack := &ProxyPacket{
			Type:     PacketTypeReverseBindAck,
			StreamID: uint32(bindPort),
			Payload:  []byte(err.Error()),
		}
		return m.sendFunc(peerID, ack.Serialize())
	}

	ack := &ProxyPacket{
		Type:     PacketTypeReverseBindAck,
		StreamID: uint32(bindPort),
	}
	return m.sendFunc(peerID, ack.Serialize())
}

// handleReverseUnbind stops the agent's reverse listener for a bind port.
func (m *Manager) handleReverseUnbind(packet *ProxyPacket) error {
	bindPort := int(packet.StreamID)
	m.mu.Lock()
	rl, ok := m.reverseListeners[bindPort]
	if ok {
		delete(m.reverseListeners, bindPort)
	}
	m.mu.Unlock()

	if ok && rl != nil {
		rl.running.Store(false)
		rl.listener.Close()
		log.Printf("Reverse listener removed: 0.0.0.0:%d", bindPort)
	}
	return nil
}

// addReverseListener binds a port on the agent and starts its accept loop.
func (m *Manager) addReverseListener(bindPort int, destAddr string, peerID [32]byte) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", bindPort))
	if err != nil {
		return fmt.Errorf("failed to bind port %d: %w", bindPort, err)
	}

	rl := &ReverseListener{
		BindPort: bindPort,
		DestAddr: destAddr,
		PeerID:   peerID,
		listener: ln,
		manager:  m,
	}
	rl.running.Store(true)

	m.mu.Lock()
	m.reverseListeners[bindPort] = rl
	m.mu.Unlock()

	go rl.acceptLoop()

	log.Printf("Reverse listener: 0.0.0.0:%d (operator will connect to %s on inbound)", bindPort, destAddr)
	return nil
}

func (rl *ReverseListener) acceptLoop() {
	for rl.running.Load() {
		conn, err := rl.listener.Accept()
		if err != nil {
			if rl.running.Load() {
				log.Printf("Reverse listener accept error: %v", err)
			}
			continue
		}
		go rl.handleInbound(conn)
	}
}

func (rl *ReverseListener) handleInbound(conn net.Conn) {
	streamID := rl.manager.nextStreamID()

	stream := &TCPStream{
		ID:      streamID,
		Conn:    conn,
		PeerID:  rl.PeerID,
		DstAddr: rl.DestAddr,
		Ready:   make(chan struct{}),
	}

	rl.manager.mu.Lock()
	rl.manager.streams[streamID] = stream
	rl.manager.mu.Unlock()

	pkt := &ProxyPacket{
		Type:     PacketTypeReverseOpen,
		StreamID: streamID,
		DstAddr:  rl.DestAddr,
	}
	if err := rl.manager.sendFunc(rl.PeerID, pkt.Serialize()); err != nil {
		log.Printf("Reverse listener: failed to send ReverseOpen: %v", err)
		conn.Close()
		rl.manager.removeStream(streamID)
		return
	}

	select {
	case <-stream.Ready:
		if stream.Error != nil {
			log.Printf("Reverse open failed for stream %d: %v", streamID, stream.Error)
			conn.Close()
			rl.manager.removeStream(streamID)
			return
		}
	case <-time.After(10 * time.Second):
		log.Printf("Reverse open timeout for stream %d", streamID)
		conn.Close()
		rl.manager.removeStream(streamID)
		// Tell operator to release its side (it may already have dialed destAddr).
		closePkt := &ProxyPacket{Type: PacketTypeTCPClose, StreamID: streamID}
		rl.manager.sendFunc(rl.PeerID, closePkt.Serialize())
		return
	}

	go rl.manager.readFromLocal(stream)
}

// SendIPPacket sends a raw IP packet to a peer (for TUN mode on operator)
func (m *Manager) SendIPPacket(peerID [32]byte, ipPacket []byte) error {
	// Prefix with packet type
	data := make([]byte, 1+len(ipPacket))
	data[0] = byte(PacketTypeIPPacket)
	copy(data[1:], ipPacket)
	return m.sendFunc(peerID, data)
}

// handleIPPacket processes an incoming IP packet from the peer
// On agent: receives packets from operator's TUN, creates real connections
// On operator: receives response packets from agent, writes to TUN
func (m *Manager) handleIPPacket(peerID [32]byte, ipPacket []byte) error {
	if len(ipPacket) < 20 {
		return fmt.Errorf("IP packet too short")
	}

	version := ipPacket[0] >> 4
	if version != 4 {
		return nil // IPv4 only for now
	}

	ihl := int(ipPacket[0]&0x0f) * 4
	if len(ipPacket) < ihl {
		return fmt.Errorf("IP header truncated")
	}

	// If we have a TUN writer, we're the operator - write packet to TUN
	m.mu.RLock()
	writer := m.tunWriter
	m.mu.RUnlock()

	if writer != nil {
		// Operator side: write response packet to TUN
		writer(ipPacket)
		return nil
	}

	// Agent side: process the packet and create real connections
	protocol := ipPacket[9]
	srcIP := net.IP(ipPacket[12:16])
	dstIP := net.IP(ipPacket[16:20])

	switch protocol {
	case 6: // TCP
		return m.handleTUNTCP(peerID, srcIP, dstIP, ipPacket[ihl:])
	case 17: // UDP
		return m.handleTUNUDP(peerID, srcIP, dstIP, ipPacket[ihl:])
	case 1: // ICMP
		return m.handleTUNICMP(peerID, srcIP, dstIP, ipPacket[ihl:])
	}

	return nil
}

// handleTUNTCP handles TCP segments from TUN
func (m *Manager) handleTUNTCP(peerID [32]byte, srcIP, dstIP net.IP, tcpSegment []byte) error {
	if len(tcpSegment) < 20 {
		return fmt.Errorf("TCP segment too short")
	}

	srcPort := binary.BigEndian.Uint16(tcpSegment[0:2])
	dstPort := binary.BigEndian.Uint16(tcpSegment[2:4])
	seqNum := binary.BigEndian.Uint32(tcpSegment[4:8])
	ackNum := binary.BigEndian.Uint32(tcpSegment[8:12])
	dataOffset := int(tcpSegment[12]>>4) * 4
	flags := tcpSegment[13]

	isSYN := (flags & 0x02) != 0
	isACK := (flags & 0x10) != 0
	isFIN := (flags & 0x01) != 0
	isRST := (flags & 0x04) != 0

	connKey := fmt.Sprintf("%s:%d-%s:%d", srcIP, srcPort, dstIP, dstPort)

	m.mu.Lock()
	tc := m.tunConns[connKey]
	m.mu.Unlock()

	if isRST {
		// Connection reset
		if tc != nil {
			m.closeTUNConn(connKey)
		}
		return nil
	}

	if isSYN && !isACK {
		// New connection request — SYN.
		//
		// We reserve the connKey slot synchronously and run the actual
		// net.Dial on a goroutine. This:
		//   - prevents the operator's SYN retransmits from spawning
		//     parallel dials to the same target;
		//   - keeps the receive path from blocking on slow targets.
		//
		// On dial failure we DROP the entry. We only emit a TCP RST for
		// errors that genuinely mean "port is closed/unreachable"; on a
		// timeout we stay silent so the operator's kernel never sees a
		// SYN-ACK and the scan correctly reports `filtered` (vs `closed`).
		m.mu.Lock()
		if _, exists := m.tunConns[connKey]; exists {
			// Already dialing or established — drop duplicate SYN.
			m.mu.Unlock()
			return nil
		}
		tc = &TUNConn{
			SrcIP:    srcIP,
			DstIP:    dstIP,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			SeqNum:   1000, // initial seq for our (fake) side of the conn
			AckNum:   seqNum + 1,
			State:    TCPStateConnecting,
			PeerID:   peerID,
			LastSeen: time.Now(),
		}
		m.tunConns[connKey] = tc
		m.mu.Unlock()

		addr := fmt.Sprintf("%s:%d", dstIP, dstPort)
		log.Printf("TUN: TCP SYN %s:%d -> %s", srcIP, srcPort, addr)

		go m.dialAndHandshake(peerID, connKey, tc, addr, ackNum, seqNum)
		return nil
	}

	// If a non-SYN packet arrives while the dial is still in flight,
	// drop it — we don't have an Encryptor or real Conn yet.
	if tc != nil {
		tc.mu.Lock()
		connecting := tc.State == TCPStateConnecting
		tc.mu.Unlock()
		if connecting {
			return nil
		}
	}

	if tc == nil {
		// No connection, send RST
		if !isRST {
			m.sendTCPReset(peerID, dstIP, srcIP, dstPort, srcPort, ackNum, seqNum+1)
		}
		return nil
	}

	tc.mu.Lock()
	tc.LastSeen = time.Now()

	if isSYN && isACK {
		// Should not receive SYN-ACK as agent
		tc.mu.Unlock()
		return nil
	}

	if isACK && tc.State == TCPStateSynReceived {
		// Connection established
		tc.State = TCPStateEstablished
		log.Printf("TUN: TCP established %s:%d -> %s:%d", srcIP, srcPort, dstIP, dstPort)
	}

	// Handle data. The operator's kernel will retransmit a segment if our
	// synthesized ACK is lost on the UDP transport. We must dedup against
	// tc.AckNum (the next byte we expect) or we'd write duplicate bytes to
	// the real connection. Comparisons use int32 wraparound math since TCP
	// seq numbers are mod 2^32.
	if len(tcpSegment) > dataOffset && tc.State == TCPStateEstablished {
		data := tcpSegment[dataOffset:]
		segEnd := seqNum + uint32(len(data))

		// Already-delivered duplicate? Re-ACK so the peer stops retrying.
		if int32(segEnd-tc.AckNum) <= 0 {
			tc.mu.Unlock()
			m.sendTCPAck(peerID, tc)
			return nil
		}

		// Gap before this segment? Drop — we don't buffer. Re-ACK at the
		// byte we still expect so the peer retransmits the missing piece.
		if int32(seqNum-tc.AckNum) > 0 {
			tc.mu.Unlock()
			m.sendTCPAck(peerID, tc)
			return nil
		}

		// In-order or partial overlap: trim any already-delivered prefix.
		if int32(seqNum-tc.AckNum) < 0 {
			data = data[tc.AckNum-seqNum:]
		}
		tc.AckNum = segEnd
		tc.mu.Unlock()

		if _, err := tc.Conn.Write(data); err != nil {
			log.Printf("TUN: TCP write error: %v", err)
			m.closeTUNConn(connKey)
			m.sendTCPReset(peerID, dstIP, srcIP, dstPort, srcPort, 0, segEnd)
			return nil
		}

		m.sendTCPAck(peerID, tc)
		return nil
	}

	if isFIN {
		tc.State = TCPStateFinWait
		tc.AckNum = seqNum + 1
		tc.mu.Unlock()

		// Send FIN-ACK
		m.sendTCPFinAck(peerID, tc)
		m.closeTUNConn(connKey)
		return nil
	}

	tc.mu.Unlock()
	return nil
}

// dialAndHandshake is the second half of TUN SYN handling: dial the real
// target, then either send SYN-ACK on success or evict the reservation +
// optionally send RST on failure.
func (m *Manager) dialAndHandshake(peerID [32]byte, connKey string, tc *TUNConn, addr string, ackNum, seqNum uint32) {
	conn, err := net.DialTimeout("tcp", addr, tunDialTimeout)
	if err != nil {
		// Remove the reservation so a future scan attempt can re-dial.
		m.mu.Lock()
		// Only delete if it's still our entry (defensive).
		if cur, ok := m.tunConns[connKey]; ok && cur == tc {
			delete(m.tunConns, connKey)
		}
		m.mu.Unlock()

		// Distinguish timeout from a definite refusal/unreachable:
		//   - hard failure → RST so operator's nmap reports "closed"
		//   - timeout      → stay silent, operator's kernel retries SYN
		//                    and nmap eventually reports "filtered"
		if isTimeoutErr(err) {
			log.Printf("TUN: TCP dial timeout to %s (port shown as filtered)", addr)
		} else {
			log.Printf("TUN: TCP connect failed to %s: %v", addr, err)
			m.sendTCPReset(peerID, tc.DstIP, tc.SrcIP, tc.DstPort, tc.SrcPort, ackNum, seqNum+1)
		}
		return
	}

	tc.mu.Lock()
	tc.Conn = conn
	tc.State = TCPStateSynReceived
	tc.LastSeen = time.Now()
	tc.mu.Unlock()

	m.sendTCPSynAck(peerID, tc)
	go m.tunConnReadLoop(connKey, tc)
}

// isTimeoutErr reports whether err is (or wraps) a net timeout.
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// tunConnReadLoop reads data from the real TCP connection and sends it back as IP packets
func (m *Manager) tunConnReadLoop(connKey string, tc *TUNConn) {
	buf := make([]byte, 1400) // Leave room for headers

	for {
		tc.mu.Lock()
		if tc.State == TCPStateClosed || tc.State == TCPStateFinWait {
			tc.mu.Unlock()
			return
		}
		conn := tc.Conn
		tc.mu.Unlock()

		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				log.Printf("TUN: TCP read error: %v", err)
			}
			// Send FIN
			tc.mu.Lock()
			if tc.State == TCPStateEstablished {
				tc.State = TCPStateFinWait
				tc.mu.Unlock()
				m.sendTCPFin(tc.PeerID, tc)
			} else {
				tc.mu.Unlock()
			}
			m.closeTUNConn(connKey)
			return
		}

		tc.mu.Lock()
		// Send data as TCP packet back to operator's TUN
		m.sendTCPData(tc.PeerID, tc, buf[:n])
		tc.SeqNum += uint32(n)
		tc.mu.Unlock()
	}
}

// sendTCPSynAck sends a SYN-ACK packet
func (m *Manager) sendTCPSynAck(peerID [32]byte, tc *TUNConn) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Build TCP header with SYN-ACK flags
	tcpHeader := m.buildTCPHeader(tc.DstPort, tc.SrcPort, tc.SeqNum, tc.AckNum, 0x12, nil) // SYN+ACK
	ipPacket := m.buildIPv4Packet(tc.DstIP, tc.SrcIP, 6, tcpHeader)

	m.SendIPPacket(peerID, ipPacket)
	tc.SeqNum++ // SYN consumes one sequence number
}

// sendTCPAck sends an ACK packet
func (m *Manager) sendTCPAck(peerID [32]byte, tc *TUNConn) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tcpHeader := m.buildTCPHeader(tc.DstPort, tc.SrcPort, tc.SeqNum, tc.AckNum, 0x10, nil) // ACK
	ipPacket := m.buildIPv4Packet(tc.DstIP, tc.SrcIP, 6, tcpHeader)

	m.SendIPPacket(peerID, ipPacket)
}

// sendTCPData sends a TCP data packet
func (m *Manager) sendTCPData(peerID [32]byte, tc *TUNConn, data []byte) {
	// tc.mu already locked by caller
	tcpHeader := m.buildTCPHeader(tc.DstPort, tc.SrcPort, tc.SeqNum, tc.AckNum, 0x18, data) // PSH+ACK
	ipPacket := m.buildIPv4Packet(tc.DstIP, tc.SrcIP, 6, tcpHeader)

	m.SendIPPacket(peerID, ipPacket)
}

// sendTCPFin sends a FIN packet
func (m *Manager) sendTCPFin(peerID [32]byte, tc *TUNConn) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tcpHeader := m.buildTCPHeader(tc.DstPort, tc.SrcPort, tc.SeqNum, tc.AckNum, 0x11, nil) // FIN+ACK
	ipPacket := m.buildIPv4Packet(tc.DstIP, tc.SrcIP, 6, tcpHeader)

	m.SendIPPacket(peerID, ipPacket)
}

// sendTCPFinAck sends a FIN-ACK packet
func (m *Manager) sendTCPFinAck(peerID [32]byte, tc *TUNConn) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tcpHeader := m.buildTCPHeader(tc.DstPort, tc.SrcPort, tc.SeqNum, tc.AckNum, 0x11, nil) // FIN+ACK
	ipPacket := m.buildIPv4Packet(tc.DstIP, tc.SrcIP, 6, tcpHeader)

	m.SendIPPacket(peerID, ipPacket)
}

// sendTCPReset sends a RST packet
func (m *Manager) sendTCPReset(peerID [32]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, seqNum, ackNum uint32) {
	tcpHeader := m.buildTCPHeader(srcPort, dstPort, seqNum, ackNum, 0x14, nil) // RST+ACK
	ipPacket := m.buildIPv4Packet(srcIP, dstIP, 6, tcpHeader)

	m.SendIPPacket(peerID, ipPacket)
}

// buildTCPHeader builds a TCP header
func (m *Manager) buildTCPHeader(srcPort, dstPort uint16, seqNum, ackNum uint32, flags byte, data []byte) []byte {
	headerLen := 20 // No options
	totalLen := headerLen + len(data)
	header := make([]byte, totalLen)

	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	binary.BigEndian.PutUint32(header[4:8], seqNum)
	binary.BigEndian.PutUint32(header[8:12], ackNum)
	header[12] = byte(headerLen/4) << 4 // Data offset
	header[13] = flags
	binary.BigEndian.PutUint16(header[14:16], 65535) // Window size
	// Checksum at [16:18] - calculated later
	// Urgent pointer at [18:20] - 0

	if len(data) > 0 {
		copy(header[headerLen:], data)
	}

	return header
}

// buildIPv4Packet builds an IPv4 packet
func (m *Manager) buildIPv4Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) []byte {
	headerLen := 20 // No options
	totalLen := headerLen + len(payload)

	packet := make([]byte, totalLen)

	packet[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	packet[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(packet[4:6], 0)      // ID
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Flags: Don't fragment
	packet[8] = 64                                  // TTL
	packet[9] = protocol
	// Checksum at [10:12] - calculated below
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// Calculate IP header checksum
	var sum uint32
	for i := 0; i < headerLen; i += 2 {
		sum += uint32(packet[i])<<8 | uint32(packet[i+1])
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	copy(packet[headerLen:], payload)

	// Calculate TCP/UDP checksum if needed
	if protocol == 6 && len(payload) >= 20 {
		m.calculateTCPChecksum(packet, srcIP, dstIP, payload)
	}

	return packet
}

// calculateTCPChecksum calculates and sets the TCP checksum
func (m *Manager) calculateTCPChecksum(ipPacket []byte, srcIP, dstIP net.IP, tcpSegment []byte) {
	// Pseudo header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6 // TCP
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpSegment)))

	// Clear existing checksum
	tcpSegment[16] = 0
	tcpSegment[17] = 0

	var sum uint32

	// Sum pseudo header
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(pseudoHeader[i])<<8 | uint32(pseudoHeader[i+1])
	}

	// Sum TCP segment
	for i := 0; i < len(tcpSegment)-1; i += 2 {
		sum += uint32(tcpSegment[i])<<8 | uint32(tcpSegment[i+1])
	}
	if len(tcpSegment)%2 == 1 {
		sum += uint32(tcpSegment[len(tcpSegment)-1]) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	checksum := ^uint16(sum)
	binary.BigEndian.PutUint16(tcpSegment[16:18], checksum)

	// Update in the IP packet
	copy(ipPacket[20:20+len(tcpSegment)], tcpSegment)
}

// closeTUNConn closes a TUN connection
func (m *Manager) closeTUNConn(connKey string) {
	m.mu.Lock()
	tc, ok := m.tunConns[connKey]
	if ok {
		delete(m.tunConns, connKey)
	}
	m.mu.Unlock()

	if ok && tc != nil {
		tc.mu.Lock()
		tc.State = TCPStateClosed
		if tc.Conn != nil {
			tc.Conn.Close()
		}
		tc.mu.Unlock()
	}
}

// handleTUNUDP handles UDP datagrams from TUN
func (m *Manager) handleTUNUDP(peerID [32]byte, srcIP, dstIP net.IP, udpDatagram []byte) error {
	if len(udpDatagram) < 8 {
		return fmt.Errorf("UDP datagram too short")
	}

	srcPort := binary.BigEndian.Uint16(udpDatagram[0:2])
	dstPort := binary.BigEndian.Uint16(udpDatagram[2:4])
	data := udpDatagram[8:]

	addr := fmt.Sprintf("%s:%d", dstIP, dstPort)
	log.Printf("TUN: UDP %s:%d -> %s (%d bytes)", srcIP, srcPort, addr, len(data))

	// Send UDP and get response
	conn, err := net.DialTimeout("udp", addr, 5*time.Second)
	if err != nil {
		log.Printf("TUN: UDP dial failed: %v", err)
		return err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(data)
	if err != nil {
		return err
	}

	// Read response
	respBuf := make([]byte, 1500)
	n, err := conn.Read(respBuf)
	if err != nil {
		// No response is okay for UDP
		return nil
	}

	// Send response back
	m.sendUDPResponse(peerID, dstIP, srcIP, dstPort, srcPort, respBuf[:n])
	return nil
}

// sendUDPResponse sends a UDP response packet
func (m *Manager) sendUDPResponse(peerID [32]byte, srcIP, dstIP net.IP, srcPort, dstPort uint16, data []byte) {
	udpHeader := make([]byte, 8+len(data))
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(8+len(data)))
	// Checksum optional for IPv4, leave as 0
	copy(udpHeader[8:], data)

	ipPacket := m.buildIPv4Packet(srcIP, dstIP, 17, udpHeader)
	m.SendIPPacket(peerID, ipPacket)
}

// handleTUNICMP handles ICMP packets from TUN
func (m *Manager) handleTUNICMP(peerID [32]byte, srcIP, dstIP net.IP, icmpData []byte) error {
	if len(icmpData) < 8 {
		return fmt.Errorf("ICMP packet too short")
	}

	icmpType := icmpData[0]
	if icmpType != 8 { // Echo request
		return nil
	}

	log.Printf("TUN: ICMP echo request to %s", dstIP)

	// Try to ping
	conn, err := net.DialTimeout("ip4:icmp", dstIP.String(), 5*time.Second)
	if err != nil {
		// ICMP might require root, send unreachable
		log.Printf("TUN: ICMP dial failed (may need root): %v", err)
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(icmpData)
	if err != nil {
		return nil
	}

	respBuf := make([]byte, 1500)
	n, err := conn.Read(respBuf)
	if err != nil {
		return nil
	}

	// Send echo reply back (swap src/dst)
	ipPacket := m.buildIPv4Packet(dstIP, srcIP, 1, respBuf[:n])
	m.SendIPPacket(peerID, ipPacket)
	return nil
}
