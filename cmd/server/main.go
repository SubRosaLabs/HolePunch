// HolePunch Orchestration Server
// Coordinates UDP hole punching between clients
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/config"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// ClientInfo stores information about a connected client
type ClientInfo struct {
	ID        [32]byte
	PublicKey [32]byte
	Addr      *net.UDPAddr
	LastSeen  time.Time
}

// Server is the orchestration server
type Server struct {
	conn       *net.UDPConn
	clients    map[[32]byte]*ClientInfo
	mu         sync.RWMutex
	shutdown   chan struct{}
	maxClients int
	stats      *config.Stats
}

// NewServer creates a new orchestration server
func NewServer(addr string, useIPv6 bool, maxClients int) (*Server, error) {
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

	return &Server{
		conn:       conn,
		clients:    make(map[[32]byte]*ClientInfo),
		shutdown:   make(chan struct{}),
		maxClients: maxClients,
		stats:      config.NewStats(),
	}, nil
}

// Run starts the server
func (s *Server) Run() error {
	log.Printf("%s", config.VersionInfo())
	log.Printf("Listening on %s (max clients: %d)", s.conn.LocalAddr().String(), s.maxClients)

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
	default:
		log.Printf("Unknown message type %d from %s", header.Type, addr.String())
	}
}

func (s *Server) handleRegister(data []byte, addr *net.UDPAddr) {
	msg, err := protocol.ParseRegisterMessage(data)
	if err != nil {
		log.Printf("Failed to parse register message: %v", err)
		return
	}

	s.mu.Lock()
	// Check if client already exists (re-registration)
	_, exists := s.clients[msg.ClientID]
	if !exists && len(s.clients) >= s.maxClients {
		s.mu.Unlock()
		log.Printf("Rejected client %s: max clients reached (%d)", hex.EncodeToString(msg.ClientID[:8]), s.maxClients)
		return
	}

	client := &ClientInfo{
		ID:        msg.ClientID,
		PublicKey: msg.PublicKey,
		Addr:      addr,
		LastSeen:  time.Now(),
	}
	s.clients[msg.ClientID] = client
	s.mu.Unlock()

	s.stats.AddConnection()
	log.Printf("Client registered: %s from %s (total: %d)", hex.EncodeToString(msg.ClientID[:8]), addr.String(), len(s.clients))

	// Send acknowledgment
	ack := protocol.Header{Version: 1, Type: protocol.MsgTypeRegisterAck, Length: 0}
	s.conn.WriteToUDP(ack.Serialize(), addr)

	// Send peer list to all clients
	s.broadcastPeerList()
}

func (s *Server) handlePunchRequest(data []byte, addr *net.UDPAddr) {
	if len(data) < 32 {
		log.Printf("Punch request too short from %s", addr.String())
		return
	}

	var targetID [32]byte
	copy(targetID[:], data[:32])

	// Find the requesting client
	var requester *ClientInfo
	s.mu.RLock()
	for _, c := range s.clients {
		if c.Addr.IP.Equal(addr.IP) && c.Addr.Port == addr.Port {
			requester = c
			break
		}
	}
	target := s.clients[targetID]
	s.mu.RUnlock()

	if requester == nil {
		log.Printf("Punch request from unknown client %s", addr.String())
		return
	}

	if target == nil {
		log.Printf("Punch request for unknown target %s", hex.EncodeToString(targetID[:8]))
		return
	}

	log.Printf("Punch request: %s -> %s",
		hex.EncodeToString(requester.ID[:8]),
		hex.EncodeToString(target.ID[:8]))

	// Send punch init to both clients
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

	for _, client := range s.clients {
		if client.Addr.IP.Equal(addr.IP) && client.Addr.Port == addr.Port {
			client.LastSeen = time.Now()
			break
		}
	}
}

func (s *Server) handleDisconnect(data []byte, addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, client := range s.clients {
		if client.Addr.IP.Equal(addr.IP) && client.Addr.Port == addr.Port {
			delete(s.clients, id)
			log.Printf("Client disconnected: %s", hex.EncodeToString(id[:8]))
			break
		}
	}
}

func (s *Server) broadcastPeerList() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build peer list for each client (excluding themselves)
	for clientID, client := range s.clients {
		var peerData []byte
		peerCount := 0

		for peerID, peer := range s.clients {
			if peerID == clientID {
				continue
			}

			peerData = append(peerData, peer.ID[:]...)
			peerData = append(peerData, peer.PublicKey[:]...)

			addrBytes := peer.Addr.IP.To4()
			if addrBytes == nil {
				addrBytes = peer.Addr.IP.To16()
			}

			portBytes := make([]byte, 2)
			portBytes[0] = byte(peer.Addr.Port >> 8)
			portBytes[1] = byte(peer.Addr.Port)
			peerData = append(peerData, portBytes...)
			peerData = append(peerData, byte(len(addrBytes)))
			peerData = append(peerData, addrBytes...)

			peerCount++
		}

		if peerCount > 0 {
			header := protocol.Header{
				Version: 1,
				Type:    protocol.MsgTypePeerList,
				Length:  uint16(1 + len(peerData)),
			}
			msg := header.Serialize()
			msg = append(msg, byte(peerCount))
			msg = append(msg, peerData...)

			s.conn.WriteToUDP(msg, client.Addr)
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
			for id, client := range s.clients {
				if time.Since(client.LastSeen) > 2*time.Minute {
					delete(s.clients, id)
					log.Printf("Client timed out: %s", hex.EncodeToString(id[:8]))
				}
			}
			s.mu.Unlock()
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
			fmt.Println("  clients          List connected clients")
			fmt.Println("  stats            Show traffic statistics")
			fmt.Println("  version          Show version info")
			fmt.Println("  quit, exit       Shut down the orchestrator")
		case "clients", "peers":
			s.cmdClients()
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
		fmt.Printf("  %s at %s (last seen %s ago)\n",
			hex.EncodeToString(c.ID[:8]),
			c.Addr.String(),
			config.FormatDuration(now.Sub(c.LastSeen)))
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
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(config.VersionInfo())
		os.Exit(0)
	}

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	server, err := NewServer(addr, *ipv6, *maxClients)
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
