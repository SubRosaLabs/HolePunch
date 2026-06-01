// HolePunch Orchestration Server
// Coordinates UDP hole punching between clients
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/auth"
	"github.com/abb3rrant/HolePunch/pkg/config"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// Role distinguishes passive agents from authenticated operators. Operators
// have proved possession of an Ed25519 key whose public half appears in the
// orchestrator's authorized_keys file; only they may request punches and
// receive the peer list.
type Role uint8

const (
	RoleAgent    Role = 0
	RoleOperator Role = 1
)

func (r Role) String() string {
	if r == RoleOperator {
		return "operator"
	}
	return "agent"
}

// ClientInfo stores information about a connected client.
type ClientInfo struct {
	ID           [32]byte
	PublicKey    [32]byte // X25519 traffic key
	Addr         *net.UDPAddr
	LastSeen     time.Time
	Role         Role
	SessionNonce [32]byte                 // Server-generated per registration; client signs this to auth as operator
	EdPubKey     [auth.PublicKeySize]byte // Set when authenticated; zero for agents
}

// Server is the orchestration server.
type Server struct {
	conn       *net.UDPConn
	clients    map[[32]byte]*ClientInfo
	mu         sync.RWMutex
	shutdown   chan struct{}
	maxClients int
	stats      *config.Stats
	authorized auth.AuthorizedKeys
	authPath   string
}

// NewServer creates a new orchestration server. authPath points at the
// operator authorized_keys file; a missing/empty file is not fatal — the
// server runs with zero operators allowed and logs a warning.
func NewServer(addr string, useIPv6 bool, maxClients int, authPath string) (*Server, error) {
	network := "udp4"
	if useIPv6 {
		network = "udp6"
	}

	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen: %w", err)
	}

	authorized, err := auth.LoadAuthorizedKeys(authPath)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("load authorized_keys %s: %w", authPath, err)
	}

	return &Server{
		conn:       conn,
		clients:    make(map[[32]byte]*ClientInfo),
		shutdown:   make(chan struct{}),
		maxClients: maxClients,
		stats:      config.NewStats(),
		authorized: authorized,
		authPath:   authPath,
	}, nil
}

// Run starts the server
func (s *Server) Run() error {
	log.Printf("%s", config.VersionInfo())
	log.Printf("Listening on %s (max clients: %d)", s.conn.LocalAddr().String(), s.maxClients)
	if len(s.authorized) == 0 {
		log.Printf("WARNING: no operator keys loaded from %s — all clients will be agent-only", s.authPath)
	} else {
		log.Printf("Loaded %d operator key(s) from %s", len(s.authorized), s.authPath)
	}

	// Start cleanup goroutine
	go s.cleanupStaleClients()
	go s.logStats()
	// Read-only interactive CLI (TTY only).
	go s.interactiveMode()

	buf := make([]byte, 65535)
	for {
		select {
		case <-s.shutdown:
			return nil
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		s.stats.AddBytesReceived(uint64(n))
		s.stats.AddPacketsReceived(1)
		go s.handlePacket(buf[:n], addr)
	}
}

func (s *Server) handlePacket(data []byte, addr *net.UDPAddr) {
	if len(data) < protocol.HeaderSize {
		log.Printf("Packet too small from %s", addr.String())
		return
	}

	header, err := protocol.ParseHeader(data)
	if err != nil {
		log.Printf("Failed to parse header: %v", err)
		return
	}

	if header.Version != protocol.WireVersion {
		log.Printf("Protocol version mismatch from %s: got v%d, want v%d",
			addr.String(), header.Version, protocol.WireVersion)
		return
	}

	payload := data[protocol.HeaderSize:]

	switch header.Type {
	case protocol.MsgTypeRegister:
		s.handleRegister(payload, addr)
	case protocol.MsgTypePunchRequest:
		s.handlePunchRequest(payload, addr)
	case protocol.MsgTypeKeepalive:
		s.handleKeepalive(addr)
	case protocol.MsgTypeDisconnect:
		s.handleDisconnect(payload, addr)
	case protocol.MsgTypeAuthRequest:
		s.handleAuthRequest(payload, addr)
	default:
		log.Printf("Unknown message type %d from %s", header.Type, addr.String())
	}
}

// clientByAddrLocked finds the registered client whose Addr matches addr.
// Caller must hold s.mu (R or W). Returns nil if no such client.
func (s *Server) clientByAddrLocked(addr *net.UDPAddr) *ClientInfo {
	for _, c := range s.clients {
		if c.Addr.IP.Equal(addr.IP) && c.Addr.Port == addr.Port {
			return c
		}
	}
	return nil
}

func (s *Server) handleRegister(data []byte, addr *net.UDPAddr) {
	msg, err := protocol.ParseRegisterMessage(data)
	if err != nil {
		log.Printf("Failed to parse register message: %v", err)
		return
	}

	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Printf("Failed to generate session nonce: %v", err)
		return
	}

	s.mu.Lock()
	// Re-registration (same ClientID) is treated as a fresh session: nonce
	// is regenerated, role drops back to agent. Operators that reconnect
	// must re-auth from the new nonce.
	_, exists := s.clients[msg.ClientID]
	if !exists && len(s.clients) >= s.maxClients {
		s.mu.Unlock()
		log.Printf("Rejected client %s: max clients reached (%d)", hex.EncodeToString(msg.ClientID[:8]), s.maxClients)
		return
	}

	client := &ClientInfo{
		ID:           msg.ClientID,
		PublicKey:    msg.PublicKey,
		Addr:         addr,
		LastSeen:     time.Now(),
		Role:         RoleAgent,
		SessionNonce: nonce,
	}
	s.clients[msg.ClientID] = client
	clientCount := len(s.clients)
	s.mu.Unlock()

	s.stats.AddConnection()
	log.Printf("Client registered: %s from %s (total: %d)", hex.EncodeToString(msg.ClientID[:8]), addr.String(), clientCount)

	// Send register ack with the session nonce the client must sign to
	// upgrade to operator role.
	ack := &protocol.RegisterAckMessage{SessionNonce: nonce}
	s.conn.WriteToUDP(ack.Serialize(), addr)

	// New client joining the fleet — notify existing operators. (The new
	// client gets its peer list only after successful auth, not here.)
	s.broadcastPeerListToOperators()
}

func (s *Server) handleAuthRequest(data []byte, addr *net.UDPAddr) {
	msg, err := protocol.ParseAuthRequestMessage(data)
	if err != nil {
		log.Printf("Auth request parse error from %s: %v", addr.String(), err)
		return
	}

	s.mu.RLock()
	client := s.clientByAddrLocked(addr)
	s.mu.RUnlock()
	if client == nil {
		log.Printf("Auth request from unregistered source %s", addr.String())
		return
	}

	granted := auth.Verify(msg.PublicKey, client.SessionNonce, client.ID, msg.Signature) &&
		s.authorized.Contains(msg.PublicKey)

	if granted {
		s.mu.Lock()
		client.Role = RoleOperator
		client.EdPubKey = msg.PublicKey
		s.mu.Unlock()

		label := s.authorized[msg.PublicKey]
		if label == "" {
			label = "(no label)"
		}
		log.Printf("Operator authenticated: %s (%s) from %s",
			auth.Fingerprint(msg.PublicKey), label, addr.String())
	} else {
		log.Printf("Auth denied for client %s at %s (pubkey=%s)",
			hex.EncodeToString(client.ID[:8]), addr.String(), auth.Fingerprint(msg.PublicKey))
	}

	result := &protocol.AuthResultMessage{Granted: granted}
	s.conn.WriteToUDP(result.Serialize(), addr)

	if granted {
		// Send the current fleet to the newly-promoted operator.
		s.mu.RLock()
		s.sendPeerListToLocked(client)
		s.mu.RUnlock()
	}
}

func (s *Server) handlePunchRequest(data []byte, addr *net.UDPAddr) {
	if len(data) < 32 {
		log.Printf("Punch request too short from %s", addr.String())
		return
	}

	var targetID [32]byte
	copy(targetID[:], data[:32])

	s.mu.RLock()
	requester := s.clientByAddrLocked(addr)
	target := s.clients[targetID]
	s.mu.RUnlock()

	if requester == nil {
		log.Printf("Punch request from unknown client %s", addr.String())
		return
	}
	if requester.Role != RoleOperator {
		log.Printf("Punch request REJECTED: client %s at %s is not an authenticated operator",
			hex.EncodeToString(requester.ID[:8]), addr.String())
		return
	}
	if target == nil {
		log.Printf("Punch request for unknown target %s", hex.EncodeToString(targetID[:8]))
		return
	}

	log.Printf("Punch: %s -> %s",
		hex.EncodeToString(requester.ID[:8]),
		hex.EncodeToString(target.ID[:8]))

	// Tell requester about target
	toRequester := &protocol.PunchInitMessage{
		PeerID:        target.ID,
		PeerPublicKey: target.PublicKey,
		PeerAddr:      target.Addr,
	}
	s.conn.WriteToUDP(toRequester.Serialize(), requester.Addr)

	// Tell target about requester
	toTarget := &protocol.PunchInitMessage{
		PeerID:        requester.ID,
		PeerPublicKey: requester.PublicKey,
		PeerAddr:      requester.Addr,
	}
	s.conn.WriteToUDP(toTarget.Serialize(), target.Addr)
}

func (s *Server) handleKeepalive(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if c := s.clientByAddrLocked(addr); c != nil {
		c.LastSeen = time.Now()
	}
}

func (s *Server) handleDisconnect(data []byte, addr *net.UDPAddr) {
	s.mu.Lock()
	var removed bool
	if c := s.clientByAddrLocked(addr); c != nil {
		delete(s.clients, c.ID)
		log.Printf("Client disconnected: %s", hex.EncodeToString(c.ID[:8]))
		removed = true
	}
	s.mu.Unlock()

	if removed {
		s.broadcastPeerListToOperators()
	}
}

// sendPeerListToLocked sends the current fleet (all clients except recipient)
// to a specific client. Caller must hold s.mu (R is enough).
func (s *Server) sendPeerListToLocked(recipient *ClientInfo) {
	var peerData []byte
	peerCount := 0

	for peerID, peer := range s.clients {
		if peerID == recipient.ID {
			continue
		}

		peerData = append(peerData, peer.ID[:]...)
		peerData = append(peerData, peer.PublicKey[:]...)

		addrBytes := peer.Addr.IP.To4()
		if addrBytes == nil {
			addrBytes = peer.Addr.IP.To16()
		}

		portBytes := []byte{byte(peer.Addr.Port >> 8), byte(peer.Addr.Port)}
		peerData = append(peerData, portBytes...)
		peerData = append(peerData, byte(len(addrBytes)))
		peerData = append(peerData, addrBytes...)

		peerCount++
	}

	if peerCount == 0 {
		return
	}

	header := protocol.Header{
		Version: protocol.WireVersion,
		Type:    protocol.MsgTypePeerList,
		Length:  uint16(1 + len(peerData)),
	}
	msg := header.Serialize()
	msg = append(msg, byte(peerCount))
	msg = append(msg, peerData...)
	s.conn.WriteToUDP(msg, recipient.Addr)
}

// broadcastPeerListToOperators sends an updated fleet view to every connected
// operator. Agents never receive this — keeping a captured agent binary from
// enumerating the rest of the fleet is the entire point of operator auth.
func (s *Server) broadcastPeerListToOperators() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, c := range s.clients {
		if c.Role == RoleOperator {
			s.sendPeerListToLocked(c)
		}
	}
}

func (s *Server) cleanupStaleClients() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
			s.mu.Lock()
			removed := false
			for id, client := range s.clients {
				if time.Since(client.LastSeen) > 2*time.Minute {
					delete(s.clients, id)
					log.Printf("Client timed out: %s", hex.EncodeToString(id[:8]))
					removed = true
				}
			}
			s.mu.Unlock()
			if removed {
				s.broadcastPeerListToOperators()
			}
		}
	}
}

func (s *Server) logStats() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdown:
			return
		case <-ticker.C:
			snap := s.stats.Snapshot()
			s.mu.RLock()
			clientCount := len(s.clients)
			s.mu.RUnlock()
			log.Printf("Stats: clients=%d, rx=%s, tx=%s, uptime=%s",
				clientCount,
				config.FormatBytes(snap.BytesReceived),
				config.FormatBytes(snap.BytesSent),
				config.FormatDuration(snap.Uptime))
		}
	}
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() {
	log.Println("Shutting down...")
	close(s.shutdown)
	s.conn.Close()
}

// interactiveMode runs a tiny read-only CLI for the orchestrator. It is a
// no-op when stdin isn't a TTY (e.g. when running under systemd or piped),
// so daemon use isn't affected.
func (s *Server) interactiveMode() {
	if !config.StdinIsTTY() {
		return
	}

	fmt.Println()
	fmt.Println("Type 'help' for commands")

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print(config.Prompt)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			fmt.Print(config.Prompt)
			continue
		}
		args := strings.Fields(line)
		switch strings.ToLower(args[0]) {
		case "help", "?":
			fmt.Println("Commands:")
			fmt.Println("  clients          List connected clients (with role)")
			fmt.Println("  operators        List authorized operators and connection status")
			fmt.Println("  stats            Show traffic statistics")
			fmt.Println("  version          Show version info")
			fmt.Println("  quit, exit       Shut down the orchestrator")
		case "clients", "peers":
			s.cmdClients()
		case "operators":
			s.cmdOperators()
		case "stats":
			s.cmdStats()
		case "version":
			fmt.Println(config.VersionInfo())
		case "quit", "exit":
			s.Shutdown()
			return
		default:
			fmt.Printf("Unknown command: %s\n", args[0])
		}
		fmt.Print(config.Prompt)
	}
}

func (s *Server) cmdClients() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.clients) == 0 {
		fmt.Println("No clients connected")
		return
	}
	now := time.Now()
	fmt.Printf("Clients (%d):\n", len(s.clients))
	for _, c := range s.clients {
		extra := ""
		if c.Role == RoleOperator {
			label := s.authorized[c.EdPubKey]
			if label == "" {
				label = "(no label)"
			}
			extra = fmt.Sprintf("  [%s/%s]", auth.Fingerprint(c.EdPubKey), label)
		}
		fmt.Printf("  %s  %-9s  %s  (last seen %s ago)%s\n",
			hex.EncodeToString(c.ID[:8]),
			c.Role,
			c.Addr.String(),
			config.FormatDuration(now.Sub(c.LastSeen)),
			extra)
	}
}

func (s *Server) cmdOperators() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.authorized) == 0 {
		fmt.Printf("No operators authorized (file: %s)\n", s.authPath)
		return
	}

	fmt.Printf("Authorized operators (%d):\n", len(s.authorized))
	for pub, label := range s.authorized {
		conn := ""
		for _, c := range s.clients {
			if c.Role == RoleOperator && c.EdPubKey == pub {
				conn = fmt.Sprintf("  [connected from %s]", c.Addr.String())
				break
			}
		}
		shown := label
		if shown == "" {
			shown = "(no label)"
		}
		fmt.Printf("  %s  %s%s\n", auth.Fingerprint(pub), shown, conn)
	}
}

func (s *Server) cmdStats() {
	snap := s.stats.Snapshot()
	s.mu.RLock()
	clientCount := len(s.clients)
	s.mu.RUnlock()
	fmt.Printf("uptime=%s rx=%s tx=%s packets_rx=%d packets_tx=%d clients=%d connections=%d\n",
		config.FormatDuration(snap.Uptime),
		config.FormatBytes(snap.BytesReceived),
		config.FormatBytes(snap.BytesSent),
		snap.PacketsReceived,
		snap.PacketsSent,
		clientCount,
		snap.Connections)
}

func main() {
	port := flag.Int("port", 41234, "UDP port to listen on")
	bind := flag.String("bind", "0.0.0.0", "Address to bind to")
	ipv6 := flag.Bool("6", false, "Use IPv6 instead of IPv4")
	maxClients := flag.Int("max-clients", 100, "Maximum number of clients")
	authPath := flag.String("authorized-keys", "./authorized_keys", "Path to operator authorized_keys file (one base64 Ed25519 pubkey per line)")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(config.VersionInfo())
		os.Exit(0)
	}

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	server, err := NewServer(addr, *ipv6, *maxClients, *authPath)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		server.Shutdown()
	}()

	if err := server.Run(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
