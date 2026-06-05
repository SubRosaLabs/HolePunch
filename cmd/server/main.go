// HolePunch Orchestration Server
// Coordinates UDP hole punching between clients over HTTP/3
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/acme/autocert"

	"github.com/abb3rrant/HolePunch/pkg/auth"
	"github.com/abb3rrant/HolePunch/pkg/config"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// Role distinguishes passive agents from authenticated operators.
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

// clientStream wraps an HTTP/3 ResponseWriter for concurrent server→client writes.
type clientStream struct {
	mu sync.Mutex
	w  http.ResponseWriter
	f  http.Flusher
}

func (cs *clientStream) Send(data []byte) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.w.Write(data) //nolint:errcheck — broken pipe on disconnect is normal
	cs.f.Flush()
}

// ClientInfo stores information about a connected client.
type ClientInfo struct {
	ID           [32]byte
	PublicKey    [32]byte
	Addr         *net.UDPAddr             // external QUIC source = hole-punch endpoint
	LastSeen     time.Time
	Role         Role
	SessionNonce [32]byte
	EdPubKey     [auth.PublicKeySize]byte
	stream       *clientStream
}

// Server is the orchestration server.
type Server struct {
	h3server   *http3.Server
	clients    map[[32]byte]*ClientInfo
	mu         sync.RWMutex
	shutdown   chan struct{}
	maxClients int
	stats      *config.Stats
	authorized auth.AuthorizedKeys
	authPath   string
	agentPath  string
}

// NewServer creates a new orchestration server.
func NewServer(addr, agentPath, authPath string, maxClients int, tlsConf *tls.Config, webroot string) (*Server, error) {
	authorized, err := auth.LoadAuthorizedKeys(authPath)
	if err != nil {
		return nil, fmt.Errorf("load authorized_keys %s: %w", authPath, err)
	}

	s := &Server{
		clients:    make(map[[32]byte]*ClientInfo),
		shutdown:   make(chan struct{}),
		maxClients: maxClients,
		stats:      config.NewStats(),
		authorized: authorized,
		authPath:   authPath,
		agentPath:  agentPath,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(agentPath, s.agentHandler)
	if webroot != "" {
		mux.Handle("/", http.FileServer(http.Dir(webroot)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		})
	}

	s.h3server = &http3.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConf,
	}

	return s, nil
}

// Run starts the server.
func (s *Server) Run() error {
	log.Printf("%s", config.VersionInfo())
	log.Printf("Listening on %s (HTTP/3, max clients: %d)", s.h3server.Addr, s.maxClients)
	log.Printf("Agent path: %s", s.agentPath)
	if len(s.authorized) == 0 {
		log.Printf("WARNING: no operator keys loaded from %s — all clients will be agent-only", s.authPath)
	} else {
		log.Printf("Loaded %d operator key(s) from %s", len(s.authorized), s.authPath)
	}

	go s.cleanupStaleClients()
	go s.logStats()
	go s.interactiveMode()

	return s.h3server.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() {
	log.Println("Shutting down...")
	close(s.shutdown)
	s.h3server.Close()
}

// readMsg reads one framed protocol message from a stream.
func readMsg(r io.Reader) ([]byte, error) {
	hdr := make([]byte, protocol.HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	h, err := protocol.ParseHeader(hdr)
	if err != nil {
		return nil, err
	}
	if h.Length == 0 {
		return hdr, nil
	}
	payload := make([]byte, h.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return append(hdr, payload...), nil
}

// agentHandler is the HTTP/3 handler for agent/operator connections.
// The request body carries client→server messages; the response body carries
// server→client messages. Both streams stay open for the session lifetime.
func (s *Server) agentHandler(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", r.RemoteAddr)
	if err != nil {
		log.Printf("Bad remote addr %s: %v", r.RemoteAddr, err)
		http.Error(w, "bad address", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	cs := &clientStream{w: w, f: flusher}

	defer func() {
		s.removeClientByAddr(remoteAddr)
		s.broadcastPeerListToOperators()
	}()

	for {
		data, err := readMsg(r.Body)
		if err != nil {
			return
		}
		s.stats.AddBytesReceived(uint64(len(data)))
		s.stats.AddPacketsReceived(1)
		s.handleStreamMessage(data, remoteAddr, cs)
	}
}

func (s *Server) handleStreamMessage(data []byte, addr *net.UDPAddr, cs *clientStream) {
	if len(data) < protocol.HeaderSize {
		return
	}
	header, err := protocol.ParseHeader(data)
	if err != nil {
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
		s.handleRegister(payload, addr, cs)
	case protocol.MsgTypePunchRequest:
		s.handlePunchRequest(payload, addr)
	case protocol.MsgTypeKeepalive:
		s.handleKeepalive(addr)
	case protocol.MsgTypeDisconnect:
		// handled by the stream-close path in agentHandler; nothing extra needed
	case protocol.MsgTypeAuthRequest:
		s.handleAuthRequest(payload, addr)
	default:
		log.Printf("Unknown message type %d from %s", header.Type, addr.String())
	}
}

// clientByAddrLocked finds a client by their QUIC remote address.
// Caller must hold s.mu (R or W).
func (s *Server) clientByAddrLocked(addr *net.UDPAddr) *ClientInfo {
	for _, c := range s.clients {
		if c.Addr.IP.Equal(addr.IP) && c.Addr.Port == addr.Port {
			return c
		}
	}
	return nil
}

// sendTo writes data to a client's HTTP/3 response stream.
func (s *Server) sendTo(client *ClientInfo, data []byte) {
	if client.stream != nil {
		s.stats.AddBytesSent(uint64(len(data)))
		s.stats.AddPacketsSent(1)
		client.stream.Send(data)
	}
}

func (s *Server) handleRegister(data []byte, addr *net.UDPAddr, cs *clientStream) {
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
		stream:       cs,
	}
	s.clients[msg.ClientID] = client
	clientCount := len(s.clients)
	s.mu.Unlock()

	s.stats.AddConnection()
	log.Printf("Client registered: %s from %s (total: %d)",
		hex.EncodeToString(msg.ClientID[:8]), addr.String(), clientCount)

	ack := &protocol.RegisterAckMessage{SessionNonce: nonce}
	cs.Send(ack.Serialize())

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
	s.sendTo(client, result.Serialize())

	if granted {
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

	toRequester := &protocol.PunchInitMessage{
		PeerID:        target.ID,
		PeerPublicKey: target.PublicKey,
		PeerAddr:      target.Addr,
	}
	s.sendTo(requester, toRequester.Serialize())

	toTarget := &protocol.PunchInitMessage{
		PeerID:        requester.ID,
		PeerPublicKey: requester.PublicKey,
		PeerAddr:      requester.Addr,
	}
	s.sendTo(target, toTarget.Serialize())
}

func (s *Server) handleKeepalive(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.clientByAddrLocked(addr); c != nil {
		c.LastSeen = time.Now()
	}
}

func (s *Server) removeClientByAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	for id, c := range s.clients {
		if c.Addr.IP.Equal(addr.IP) && c.Addr.Port == addr.Port {
			delete(s.clients, id)
			log.Printf("Client disconnected: %s", hex.EncodeToString(id[:8]))
			break
		}
	}
	s.mu.Unlock()
}

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
	s.sendTo(recipient, msg)
}

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

// buildTLSConfig returns a *tls.Config based on the chosen mode.
func buildTLSConfig(mode, certFile, keyFile, domain, cacheDir string) (*tls.Config, error) {
	switch mode {
	case "cert":
		if certFile == "" || keyFile == "" {
			return nil, fmt.Errorf("-tls-cert and -tls-key are required for cert mode")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert/key: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil

	case "letsencrypt":
		if domain == "" {
			return nil, fmt.Errorf("-tls-domain is required for letsencrypt mode")
		}
		if cacheDir == "" {
			cacheDir = "./cert-cache"
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(domain),
			Cache:      autocert.DirCache(cacheDir),
		}
		// TCP/443 listener so the ACME TLS-ALPN-01 challenge can complete.
		// TCP and UDP on the same port coexist fine at the OS level.
		go func() {
			ln, err := tls.Listen("tcp4", ":443", m.TLSConfig())
			if err != nil {
				log.Printf("ACME challenge listener (TCP/443): %v — cert renewal may fail", err)
				return
			}
			defer ln.Close()
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					c.(*tls.Conn).Handshake() //nolint:errcheck
					c.Close()
				}(conn)
			}
		}()
		return m.TLSConfig(), nil

	case "self", "":
		return generateSelfSignedTLS()

	default:
		return nil, fmt.Errorf("unknown -tls-mode %q (use: self, cert, letsencrypt)", mode)
	}
}

// generateSelfSignedTLS creates a self-signed ECDSA certificate valid for 10 years.
func generateSelfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "holepunch"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("0.0.0.0"), net.ParseIP("::")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create cert: %w", err)
	}

	log.Printf("Generated self-signed TLS cert — agents must use -ignorecert")
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}, nil
}

func main() {
	port := flag.Int("port", config.DefaultServerPort, "UDP port to listen on")
	bind := flag.String("bind", "0.0.0.0", "Address to bind to")
	maxClients := flag.Int("max-clients", 100, "Maximum number of clients")
	authPath := flag.String("authorized-keys", "./authorized_keys", "Path to operator authorized_keys file")
	agentPath := flag.String("agent-path", "/v1/metrics", "HTTP path for agent connections")
	webroot := flag.String("webroot", "", "Directory to serve as decoy website (optional)")
	tlsMode := flag.String("tls-mode", "self", "TLS certificate mode: self, cert, letsencrypt")
	tlsCert := flag.String("tls-cert", "", "Path to TLS certificate file (cert mode)")
	tlsKey := flag.String("tls-key", "", "Path to TLS private key file (cert mode)")
	tlsDomain := flag.String("tls-domain", "", "Domain name for Let's Encrypt (letsencrypt mode)")
	tlsCache := flag.String("tls-cache", "./cert-cache", "Directory to cache Let's Encrypt certs")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(config.VersionInfo())
		os.Exit(0)
	}

	tlsConf, err := buildTLSConfig(*tlsMode, *tlsCert, *tlsKey, *tlsDomain, *tlsCache)
	if err != nil {
		log.Fatalf("TLS setup: %v", err)
	}

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	server, err := NewServer(addr, *agentPath, *authPath, *maxClients, tlsConf, *webroot)
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
