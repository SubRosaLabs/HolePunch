// HolePunch Client - Like ligolo-ng but with UDP hole punching
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/auth"
	"github.com/abb3rrant/HolePunch/pkg/config"
	"github.com/abb3rrant/HolePunch/pkg/holepunch"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
	"github.com/abb3rrant/HolePunch/pkg/proxy"
)

type Client struct {
	conn         *net.UDPConn
	serverAddr   *net.UDPAddr
	clientID     [32]byte
	keys         *holepunch.KeyPair
	puncher      *holepunch.Puncher
	peers        map[string]*PeerEntry
	peersMu      sync.RWMutex
	shutdown     chan struct{}
	proxyManager *proxy.Manager
	stats        *config.Stats
	startTime    time.Time

	// Operator auth. edPrivKey is nil when no -key was passed; in that case
	// the client runs as a passive agent and operator commands are gated off
	// in the interactive shell. sessionNonce arrives in RegisterAck and is
	// only read/written from the single receiveLoop goroutine.
	edPrivKey    ed25519.PrivateKey
	sessionNonce [32]byte

	// Tunnel state — guarded by stateMu where multi-goroutine access matters.
	// Most writes happen on the interactive command goroutine; reads from
	// tunReadLoop / tunWritePacket take the mutex. isOperator also lives here
	// so the role check is atomic against AuthResult arrival.
	stateMu       sync.RWMutex
	session       *PeerEntry
	tunnelStarted bool
	tunnelIface   string
	tunnelRoutes  []string
	tunFile       *os.File // TUN device file descriptor
	isOperator    bool
}

type PeerEntry struct {
	ID        [32]byte
	PublicKey [32]byte
	Addr      *net.UDPAddr
	Connected bool
}

// NewClient builds a client. edPrivKey is the operator Ed25519 private key
// loaded from disk via -key; pass nil to run as a passive agent (no operator
// commands available, no auth attempted).
func NewClient(serverAddr string, useIPv6 bool, edPrivKey ed25519.PrivateKey) (*Client, error) {
	network := "udp4"
	if useIPv6 {
		network = "udp6"
	}

	server, err := net.ResolveUDPAddr(network, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server: %w", err)
	}

	conn, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	clientID, err := holepunch.GenerateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	keys, err := holepunch.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	client := &Client{
		conn:       conn,
		serverAddr: server,
		clientID:   clientID,
		keys:       keys,
		peers:      make(map[string]*PeerEntry),
		shutdown:   make(chan struct{}),
		stats:      config.NewStats(),
		startTime:  time.Now(),
		edPrivKey:  edPrivKey,
	}

	client.puncher = holepunch.NewPuncher(conn, keys)
	client.puncher.SetDataHandler(client.onDataReceived)
	client.puncher.SetPeerConnectedHandler(client.onPeerConnected)
	// Wrap SendToPeer so proxy traffic is counted in client stats.
	sendFunc := func(peerID [32]byte, data []byte) error {
		err := client.puncher.SendToPeer(peerID, data)
		if err == nil {
			client.stats.AddBytesSent(uint64(len(data)))
			client.stats.AddPacketsSent(1)
		}
		return err
	}
	client.proxyManager = proxy.NewManager(sendFunc)

	return client, nil
}

func (c *Client) Run() error {
	log.Printf("Client ID: %s", hex.EncodeToString(c.clientID[:8]))
	log.Printf("Connecting to: %s", c.serverAddr.String())

	if err := c.register(); err != nil {
		return fmt.Errorf("register failed: %w", err)
	}

	go c.receiveLoop()
	go c.keepaliveLoop()
	go c.interactiveMode()

	<-c.shutdown
	return nil
}

func (c *Client) register() error {
	msg := &protocol.RegisterMessage{ClientID: c.clientID, PublicKey: c.keys.PublicKey}
	_, err := c.conn.WriteToUDP(msg.Serialize(), c.serverAddr)
	return err
}

func (c *Client) receiveLoop() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-c.shutdown:
			return
		default:
		}

		c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		c.stats.AddBytesReceived(uint64(n))
		c.stats.AddPacketsReceived(1)

		if addr.IP.Equal(c.serverAddr.IP) && addr.Port == c.serverAddr.Port {
			c.handleServerPacket(buf[:n])
		} else {
			c.puncher.HandlePacket(buf[:n], addr)
		}
	}
}

func (c *Client) handleServerPacket(data []byte) {
	if len(data) < protocol.HeaderSize {
		return
	}

	header, err := protocol.ParseHeader(data)
	if err != nil {
		return
	}

	if header.Version != protocol.WireVersion {
		log.Printf("Server protocol version mismatch: got v%d, want v%d", header.Version, protocol.WireVersion)
		return
	}

	payload := data[protocol.HeaderSize:]

	switch header.Type {
	case protocol.MsgTypeRegisterAck:
		ack, err := protocol.ParseRegisterAckMessage(payload)
		if err != nil {
			log.Printf("Failed to parse register ack: %v", err)
			return
		}
		c.sessionNonce = ack.SessionNonce
		log.Println("Registered with server")
		if c.edPrivKey != nil {
			c.sendAuthRequest()
		}

	case protocol.MsgTypeAuthResult:
		res, err := protocol.ParseAuthResultMessage(payload)
		if err != nil {
			log.Printf("Failed to parse auth result: %v", err)
			return
		}
		if res.Granted {
			c.stateMu.Lock()
			c.isOperator = true
			c.stateMu.Unlock()
			log.Println("Operator authentication granted")
		} else {
			log.Println("Operator authentication denied — continuing as agent")
		}

	case protocol.MsgTypePeerList:
		c.handlePeerList(payload)

	case protocol.MsgTypePunchInit:
		c.handlePunchInit(payload)
	}
}

// sendAuthRequest signs the server-provided session nonce and our clientID
// with our Ed25519 private key, then ships the request. Called from the
// receiveLoop goroutine right after we process RegisterAck.
func (c *Client) sendAuthRequest() {
	var pub [auth.PublicKeySize]byte
	copy(pub[:], c.edPrivKey.Public().(ed25519.PublicKey))

	sig := auth.Sign(c.edPrivKey, c.sessionNonce, c.clientID)
	msg := &protocol.AuthRequestMessage{PublicKey: pub, Signature: sig}
	c.conn.WriteToUDP(msg.Serialize(), c.serverAddr)
}

// operatorRole reports whether the server granted us operator role. Safe to
// call from any goroutine.
func (c *Client) operatorRole() bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.isOperator
}

// requireOperator gates an operator-only command. Prints a one-line refusal
// (using cmd as the verb) and returns false when the client is not yet
// authenticated.
func (c *Client) requireOperator(cmd string) bool {
	if c.operatorRole() {
		return true
	}
	fmt.Printf("%s: operator key required (start the client with -key <path>)\n", cmd)
	return false
}

func (c *Client) handlePeerList(data []byte) {
	if len(data) < 1 {
		return
	}

	count := int(data[0])
	offset := 1

	c.peersMu.Lock()
	defer c.peersMu.Unlock()

	for i := 0; i < count; i++ {
		if offset+64 > len(data) {
			break
		}

		peer := &PeerEntry{}
		copy(peer.ID[:], data[offset:offset+32])
		copy(peer.PublicKey[:], data[offset+32:offset+64])
		offset += 64

		if offset+3 > len(data) {
			break
		}

		port := binary.BigEndian.Uint16(data[offset : offset+2])
		ipLen := int(data[offset+2])
		offset += 3

		if offset+ipLen > len(data) {
			break
		}

		// Copy IP bytes out of the receive buffer so peer.Addr.IP stays
		// valid after the buffer is reused for the next UDP read.
		ipCopy := make(net.IP, ipLen)
		copy(ipCopy, data[offset:offset+ipLen])
		peer.Addr = &net.UDPAddr{
			IP:   ipCopy,
			Port: int(port),
		}
		offset += ipLen

		hexID := hex.EncodeToString(peer.ID[:8])
		if _, exists := c.peers[hexID]; !exists {
			c.peers[hexID] = peer
			log.Printf("Agent discovered: %s at %s", hexID, peer.Addr.String())
		}
	}
}

func (c *Client) handlePunchInit(data []byte) {
	msg, err := protocol.ParsePunchInitMessage(data)
	if err != nil {
		return
	}

	hexID := hex.EncodeToString(msg.PeerID[:8])
	log.Printf("Connecting to agent %s", hexID)

	if err := c.puncher.InitiatePunch(msg.PeerID, msg.PeerPublicKey, msg.PeerAddr); err != nil {
		log.Printf("Punch failed: %v", err)
	}

	c.peersMu.Lock()
	if peer, exists := c.peers[hexID]; exists {
		peer.Connected = true
	}
	c.peersMu.Unlock()
}

func (c *Client) onDataReceived(peerID [32]byte, data []byte) {
	if len(data) == 0 {
		return
	}

	if proxy.IsProxyPacket(data) {
		if err := c.proxyManager.HandlePacket(peerID, data); err != nil {
			log.Printf("Proxy packet error: %v", err)
		}
		return
	}

	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("[%s]: %s", hexID, string(data))
}

func (c *Client) onPeerConnected(peerID [32]byte) {
	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("Agent connected: %s", hexID)

	c.peersMu.Lock()
	if peer, exists := c.peers[hexID]; exists {
		peer.Connected = true
	}
	c.peersMu.Unlock()
}

func (c *Client) keepaliveLoop() {
	// : 25 second persistent keepalive
	ticker := time.NewTicker(holepunch.KeepaliveTimeout)
	defer ticker.Stop()

	keepalive := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeKeepalive, Length: 0}
	keepaliveData := keepalive.Serialize()

	for {
		select {
		case <-c.shutdown:
			return
		case <-ticker.C:
			c.conn.WriteToUDP(keepaliveData, c.serverAddr)
			c.puncher.SendKeepalive()
		}
	}
}

func (c *Client) interactiveMode() {
	scanner := bufio.NewScanner(os.Stdin)
	c.printBanner()

	// Only show the prompt when stdin is a TTY; piped/scripted use stays
	// clean (no prompt clutter in log captures).
	tty := config.StdinIsTTY()

	if tty {
		fmt.Print(config.Prompt)
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			if tty {
				fmt.Print(config.Prompt)
			}
			continue
		}

		args := strings.Fields(line)
		cmd := strings.ToLower(args[0])

		switch cmd {
		case "help", "?":
			c.printHelp()
		case "session":
			if c.requireOperator("session") {
				c.cmdSession(args[1:])
			}
		case "tunnel":
			if c.requireOperator("tunnel") {
				c.cmdTunnel(args[1:])
			}
		case "route":
			if c.requireOperator("route") {
				c.cmdRoute(args[1:])
			}
		case "ifconfig":
			if c.requireOperator("ifconfig") {
				c.cmdIfconfig()
			}
		case "agents", "peers":
			if c.requireOperator("agents") {
				c.cmdAgents()
			}
		case "listener", "forward":
			if c.requireOperator("listener") {
				c.cmdListener(args[1:])
			}
		case "rlistener":
			if c.requireOperator("rlistener") {
				c.cmdRlistener(args[1:])
			}
		case "socks":
			if c.requireOperator("socks") {
				c.cmdSocks(args[1:])
			}
		case "stats":
			c.cmdStats()
		case "version":
			c.cmdVersion()
		case "quit", "exit":
			c.Shutdown()
			return
		default:
			fmt.Printf("Unknown command: %s\n", cmd)
		}

		if tty {
			fmt.Print(config.Prompt)
		}
	}
}

func (c *Client) printBanner() {
	fmt.Println()
	fmt.Printf("  %s\n", config.VersionInfo())
	fmt.Println("  Type 'help' for commands")
	fmt.Println()
}

func (c *Client) printHelp() {
	if !c.operatorRole() {
		// Agent mode: hide operator commands entirely. A captured binary's
		// help output should look benign — no hints about what it could do
		// with an operator key.
		fmt.Print(`
Commands:
  stats                       - Show connection statistics
  version                     - Show version info
  help                        - Show this help
  quit                        - Exit
`)
		return
	}
	fmt.Print(`
Commands:
  agents                      - List connected agents
  session [id]                - Select agent for tunneling

Tunnel (Linux operator, requires sudo):
  tunnel start                - Start TUN interface
  tunnel stop                 - Stop TUN interface
  route add <cidr>            - Route network through tunnel (AllowedIP)
  route del <cidr>            - Remove route
  route list                  - Show routes
  ifconfig                    - Show tunnel info

Listeners (no root needed):
  listener add <local>:<remote>   - Forward local port to remote via agent
  listener del <port>             - Remove listener
  listener list                   - Show listeners

Reverse listeners (agent binds, operator connects):
  rlistener add <bind>:<dest>     - Agent binds port; inbound connects to your local dest
  rlistener del <port>            - Stop agent's reverse listener
  rlistener list                  - Show reverse listeners

SOCKS (no root needed):
  socks start [port]          - Start SOCKS5 proxy (default: 1080)
  socks stop                  - Stop SOCKS5 proxy

Info:
  stats                       - Show connection statistics
  version                     - Show version info
  help                        - Show this help
  quit                        - Exit
`)
}

func (c *Client) cmdStats() {
	snap := c.stats.Snapshot()
	fmt.Println("Connection Statistics:")
	fmt.Printf("  Uptime:           %s\n", config.FormatDuration(snap.Uptime))
	fmt.Printf("  Idle:             %s\n", config.FormatDuration(snap.IdleTime))
	fmt.Printf("  Bytes sent:       %s\n", config.FormatBytes(snap.BytesSent))
	fmt.Printf("  Bytes received:   %s\n", config.FormatBytes(snap.BytesReceived))
	fmt.Printf("  Packets sent:     %d\n", snap.PacketsSent)
	fmt.Printf("  Packets received: %d\n", snap.PacketsReceived)
	fmt.Printf("  Active streams:   %d\n", snap.ActiveStreams)
	fmt.Printf("  Connections:      %d\n", snap.Connections)
	if snap.ReplayBlocked > 0 {
		fmt.Printf("  Replay blocked:   %d\n", snap.ReplayBlocked)
	}
	if snap.DroppedPackets > 0 {
		fmt.Printf("  Dropped packets:  %d\n", snap.DroppedPackets)
	}
}

func (c *Client) cmdVersion() {
	fmt.Println(config.VersionInfo())
	fmt.Printf("  Go version: %s\n", runtime.Version())
	fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
}

func (c *Client) cmdAgents() {
	c.peersMu.RLock()
	defer c.peersMu.RUnlock()

	if len(c.peers) == 0 {
		fmt.Println("No agents connected")
		return
	}

	fmt.Println("\nAgents:")
	for hexID, peer := range c.peers {
		status := "waiting"
		if peer.Connected {
			status = "connected"
		}
		selected := ""
		if c.session != nil && c.session.ID == peer.ID {
			selected = " [SELECTED]"
		}
		fmt.Printf("  %s - %s (%s)%s\n", hexID, peer.Addr.String(), status, selected)
	}
	fmt.Println()
}

func (c *Client) cmdSession(args []string) {
	if len(args) == 0 {
		if c.session == nil {
			fmt.Println("No session. Use: session <agent-id>")
			return
		}
		fmt.Printf("Session: %s\n", hex.EncodeToString(c.session.ID[:8]))
		return
	}

	prefix := args[0]

	c.peersMu.RLock()
	var target *PeerEntry
	for hexID, peer := range c.peers {
		if strings.HasPrefix(hexID, prefix) {
			target = peer
			break
		}
	}
	c.peersMu.RUnlock()

	if target == nil {
		fmt.Printf("No agent: %s\n", prefix)
		return
	}

	if !target.Connected {
		header := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypePunchRequest, Length: 32}
		msg := header.Serialize()
		msg = append(msg, target.ID[:]...)
		c.conn.WriteToUDP(msg, c.serverAddr)
		fmt.Println("Connecting...")
		time.Sleep(2 * time.Second)

		c.peersMu.RLock()
		target = c.peers[hex.EncodeToString(target.ID[:8])]
		c.peersMu.RUnlock()

		if target == nil || !target.Connected {
			fmt.Println("Connection failed")
			return
		}
	}

	c.stateMu.Lock()
	c.session = target
	c.stateMu.Unlock()
	fmt.Printf("Session: %s\n", hex.EncodeToString(target.ID[:8]))
	fmt.Println("Use 'tunnel start' to begin")
}

func (c *Client) cmdTunnel(args []string) {
	if c.session == nil {
		fmt.Println("Select session first: session <id>")
		return
	}

	if len(args) == 0 {
		if c.tunnelStarted {
			fmt.Printf("Tunnel: %s (up)\n", c.tunnelIface)
		} else {
			fmt.Println("Tunnel not started")
		}
		return
	}

	switch args[0] {
	case "start":
		c.startTunnel()
	case "stop":
		c.stopTunnel()
	default:
		fmt.Println("Usage: tunnel start|stop")
	}
}

func (c *Client) startTunnel() {
	c.stateMu.RLock()
	already := c.tunnelStarted
	c.stateMu.RUnlock()
	if already {
		fmt.Println("Already started")
		return
	}

	if err := c.createTun(); err != nil {
		fmt.Printf("Failed: %v\n", err)
		return
	}

	c.stateMu.Lock()
	c.tunnelStarted = true
	iface := c.tunnelIface
	c.stateMu.Unlock()

	// Set up callback for writing response packets back to TUN
	c.proxyManager.SetTUNWriter(c.tunWritePacket)

	// Start reading packets from TUN and forwarding
	go c.tunReadLoop()

	fmt.Printf("Tunnel %s is up\n", iface)
	fmt.Println("Add routes: route add <cidr>")
}

// tunReadLoop reads packets from TUN and forwards via proxy ()
func (c *Client) tunReadLoop() {
	c.stateMu.RLock()
	tunFile := c.tunFile
	c.stateMu.RUnlock()
	if tunFile == nil {
		return
	}

	buf := make([]byte, 1500)
	for {
		c.stateMu.RLock()
		running := c.tunnelStarted
		c.stateMu.RUnlock()
		if !running {
			return
		}

		n, err := tunFile.Read(buf)
		if err != nil {
			c.stateMu.RLock()
			running := c.tunnelStarted
			c.stateMu.RUnlock()
			if running {
				log.Printf("TUN read error: %v", err)
			}
			return
		}

		if n < 20 {
			continue
		}

		// Parse IP header
		ipPacket := buf[:n]
		version := ipPacket[0] >> 4
		if version != 4 {
			continue // IPv4 only for now
		}

		// cryptokey routing: lookup peer by destination IP
		dstIP := net.IP(ipPacket[16:20])
		peer, found := c.puncher.LookupPeerByIP(dstIP)

		var targetPeerID [32]byte
		if found {
			targetPeerID = peer.PeerID
		} else {
			c.stateMu.RLock()
			session := c.session
			c.stateMu.RUnlock()
			if session != nil {
				targetPeerID = session.ID
			} else {
				continue
			}
		}

		// Forward the entire IP packet to the peer
		ipCopy := make([]byte, n)
		copy(ipCopy, ipPacket)

		if err := c.proxyManager.SendIPPacket(targetPeerID, ipCopy); err != nil {
			log.Printf("TUN: failed to send IP packet: %v", err)
		}
	}
}

// tunWritePacket writes an IP packet to the TUN interface
func (c *Client) tunWritePacket(ipPacket []byte) {
	c.stateMu.RLock()
	tunFile := c.tunFile
	running := c.tunnelStarted
	c.stateMu.RUnlock()
	if tunFile == nil || !running {
		return
	}

	if _, err := tunFile.Write(ipPacket); err != nil {
		log.Printf("TUN write error: %v", err)
	}
}

func (c *Client) stopTunnel() {
	c.stateMu.Lock()
	if !c.tunnelStarted {
		c.stateMu.Unlock()
		fmt.Println("Not started")
		return
	}
	c.tunnelStarted = false
	tunFile := c.tunFile
	c.tunFile = nil
	iface := c.tunnelIface
	routes := c.tunnelRoutes
	c.tunnelRoutes = nil
	c.stateMu.Unlock()

	if tunFile != nil {
		tunFile.Close()
	}

	for _, route := range routes {
		c.delRoute(route)
	}

	switch runtime.GOOS {
	case "linux":
		exec.Command("ip", "link", "set", "dev", iface, "down").Run()
		exec.Command("ip", "link", "del", "dev", iface).Run()
	case "darwin":
		exec.Command("ifconfig", "lo0", "-alias", "240.0.0.1").Run()
	}

	fmt.Println("Tunnel stopped")
}

func (c *Client) cmdRoute(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: route add|del|list <cidr>")
		return
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: route add <cidr>")
			return
		}
		c.addRoute(args[1])
	case "del", "delete":
		if len(args) < 2 {
			fmt.Println("Usage: route del <cidr>")
			return
		}
		c.delRoute(args[1])
	case "list":
		c.listRoutes()
	default:
		fmt.Println("Usage: route add|del|list")
	}
}

func (c *Client) addRoute(cidr string) {
	if !c.tunnelStarted {
		fmt.Println("Start tunnel first")
		return
	}

	if c.session == nil {
		fmt.Println("No session")
		return
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Invalid CIDR: %s\n", cidr)
		return
	}

	// : add AllowedIP for cryptokey routing
	if err := c.puncher.AddAllowedIP(c.session.ID, *ipnet); err != nil {
		fmt.Printf("Failed to add allowed IP: %v\n", err)
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "add", cidr, "dev", c.tunnelIface)
	case "darwin":
		cmd = exec.Command("route", "-n", "add", "-net", cidr, "240.0.0.1")
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exist") {
			fmt.Printf("Failed: %v: %s\n", err, out)
			return
		}
	}

	c.tunnelRoutes = append(c.tunnelRoutes, cidr)
	fmt.Printf("Route added: %s (AllowedIP for peer)\n", cidr)
}

func (c *Client) delRoute(cidr string) {
	_, ipnet, _ := net.ParseCIDR(cidr)

	// : remove AllowedIP
	if c.session != nil && ipnet != nil {
		c.puncher.RemoveAllowedIP(c.session.ID, *ipnet)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "del", cidr)
	case "darwin":
		cmd = exec.Command("route", "-n", "delete", "-net", cidr)
	}
	cmd.Run()

	var newRoutes []string
	for _, r := range c.tunnelRoutes {
		if r != cidr {
			newRoutes = append(newRoutes, r)
		}
	}
	c.tunnelRoutes = newRoutes
	fmt.Printf("Route removed: %s\n", cidr)
}

func (c *Client) listRoutes() {
	if len(c.tunnelRoutes) == 0 {
		fmt.Println("No routes")
		return
	}
	fmt.Println("Routes (AllowedIPs):")
	for _, r := range c.tunnelRoutes {
		peerInfo := ""
		if c.session != nil {
			peerInfo = fmt.Sprintf(" -> peer %s", hex.EncodeToString(c.session.ID[:4]))
		}
		fmt.Printf("  %s%s\n", r, peerInfo)
	}
}

func (c *Client) cmdIfconfig() {
	if !c.tunnelStarted {
		fmt.Println("Tunnel not started")
		return
	}
	fmt.Println("Interface:")
	fmt.Printf("  interface: %s\n", c.tunnelIface)
	fmt.Printf("  public key: %s\n", hex.EncodeToString(c.keys.PublicKey[:8]))
	if c.session != nil {
		fmt.Printf("\nPeer: %s\n", hex.EncodeToString(c.session.ID[:8]))
		fmt.Printf("  endpoint: %s\n", c.session.Addr.String())
		allowedIPs := c.puncher.GetPeerAllowedIPs(c.session.ID)
		if len(allowedIPs) > 0 {
			fmt.Printf("  allowed ips: ")
			for i, ip := range allowedIPs {
				if i > 0 {
					fmt.Printf(", ")
				}
				fmt.Printf("%s", ip.String())
			}
			fmt.Println()
		}
	}
}

func (c *Client) cmdListener(args []string) {
	if c.session == nil {
		fmt.Println("Select session first: session <id>")
		return
	}

	if len(args) == 0 {
		fmt.Println("Usage: listener add|del|list")
		return
	}

	switch args[0] {
	case "add":
		if len(args) < 2 {
			fmt.Println("Usage: listener add <local-port>:<remote-host:port>")
			fmt.Println("Example: listener add 8080:192.168.1.10:80")
			return
		}
		parts := strings.SplitN(args[1], ":", 2)
		if len(parts) != 2 {
			fmt.Println("Invalid format. Use: <local-port>:<remote-host:port>")
			return
		}
		localPort, err := strconv.Atoi(parts[0])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", parts[0])
			return
		}
		remoteAddr := parts[1]
		if err := c.proxyManager.AddPortForward(localPort, remoteAddr, c.session.ID); err != nil {
			fmt.Printf("Failed: %v\n", err)
			return
		}
		fmt.Printf("Listener: 127.0.0.1:%d -> %s\n", localPort, remoteAddr)

	case "del", "delete":
		if len(args) < 2 {
			fmt.Println("Usage: listener del <port>")
			return
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", args[1])
			return
		}
		c.proxyManager.RemovePortForward(port)
		fmt.Printf("Listener removed: %d\n", port)

	case "list":
		forwards := c.proxyManager.ListPortForwards()
		if len(forwards) == 0 {
			fmt.Println("No listeners")
			return
		}
		fmt.Println("Listeners:")
		for _, f := range forwards {
			fmt.Printf("  127.0.0.1:%d -> %s\n", f.LocalPort, f.RemoteAddr)
		}
	}
}

func (c *Client) cmdRlistener(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: rlistener add|del|list")
		return
	}

	switch args[0] {
	case "add":
		if c.session == nil {
			fmt.Println("Select session first: session <id>")
			return
		}
		if len(args) < 2 {
			fmt.Println("Usage: rlistener add <bind-port>:<dest-host:dest-port>")
			fmt.Println("Example: rlistener add 445:127.0.0.1:445")
			return
		}
		parts := strings.SplitN(args[1], ":", 2)
		if len(parts) != 2 {
			fmt.Println("Invalid format. Use: <bind-port>:<dest-host:dest-port>")
			return
		}
		bindPort, err := strconv.Atoi(parts[0])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", parts[0])
			return
		}
		destAddr := parts[1]
		fmt.Printf("Requesting agent to bind 0.0.0.0:%d...\n", bindPort)
		if err := c.proxyManager.AddReversePortForward(bindPort, destAddr, c.session.ID); err != nil {
			fmt.Printf("Failed: %v\n", err)
			return
		}
		fmt.Printf("Reverse listener: agent:0.0.0.0:%d -> %s\n", bindPort, destAddr)

	case "del", "delete":
		if c.session == nil {
			fmt.Println("Select session first: session <id>")
			return
		}
		if len(args) < 2 {
			fmt.Println("Usage: rlistener del <port>")
			return
		}
		port, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("Invalid port: %s\n", args[1])
			return
		}
		if err := c.proxyManager.RemoveReversePortForward(port); err != nil {
			fmt.Printf("Failed: %v\n", err)
			return
		}
		fmt.Printf("Reverse listener removed: %d\n", port)

	case "list":
		fwds := c.proxyManager.ListReversePortForwards()
		if len(fwds) == 0 {
			fmt.Println("No reverse listeners")
			return
		}
		fmt.Println("Reverse Listeners:")
		for _, f := range fwds {
			fmt.Printf("  agent:0.0.0.0:%d -> %s\n", f.BindPort, f.DestAddr)
		}

	default:
		fmt.Println("Usage: rlistener add|del|list")
	}
}

func (c *Client) cmdSocks(args []string) {
	if len(args) == 0 {
		port := c.proxyManager.GetSOCKS5Port()
		if port > 0 {
			fmt.Printf("SOCKS5: 127.0.0.1:%d\n", port)
		} else {
			fmt.Println("SOCKS5 not running")
		}
		return
	}

	switch args[0] {
	case "start":
		if c.session == nil {
			fmt.Println("Select session first: session <id>")
			return
		}
		port := 1080
		if len(args) > 1 {
			p, err := strconv.Atoi(args[1])
			if err == nil {
				port = p
			}
		}
		if err := c.proxyManager.StartSOCKS5(port, c.session.ID); err != nil {
			fmt.Printf("Failed: %v\n", err)
			return
		}
		fmt.Printf("SOCKS5 started: 127.0.0.1:%d\n", port)
		fmt.Println("Usage examples:")
		fmt.Printf("  curl --socks5 127.0.0.1:%d http://target\n", port)
		fmt.Printf("  proxychains nmap -sT target\n")

	case "stop":
		c.proxyManager.StopSOCKS5()
		fmt.Println("SOCKS5 stopped")
	}
}

func (c *Client) Shutdown() {
	if c.tunnelStarted {
		c.stopTunnel()
	}
	if c.proxyManager != nil {
		c.proxyManager.Close()
	}
	header := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeDisconnect, Length: 0}
	c.conn.WriteToUDP(header.Serialize(), c.serverAddr)
	close(c.shutdown)
	c.conn.Close()
}

// runKeygen generates an Ed25519 operator keypair at path (private) and
// path+".pub" (public, authorized_keys-line format). Refuses to overwrite
// existing files — losing a key silently is far worse than a one-line error.
func runKeygen(path string) error {
	for _, p := range []string{path, path + ".pub"} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists — refusing to overwrite", p)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", p, err)
		}
	}

	pub, priv, err := auth.GenerateKeypair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	label := ""
	if host, err := os.Hostname(); err == nil && host != "" {
		label = "operator@" + host
	}

	if err := auth.SavePrivateKey(path, priv); err != nil {
		return fmt.Errorf("save private key: %w", err)
	}
	if err := auth.SavePublicKey(path+".pub", pub, label); err != nil {
		return fmt.Errorf("save public key: %w", err)
	}

	fmt.Println("Generated Ed25519 operator keypair:")
	fmt.Printf("  private: %s (0600)\n", path)
	fmt.Printf("  public:  %s (0644)\n", path+".pub")
	fmt.Println()
	fmt.Println("Add this line to the orchestrator's authorized_keys file:")
	line := auth.EncodePublicKey(pub)
	if label != "" {
		line += " # " + label
	}
	fmt.Println("  " + line)
	return nil
}

func main() {
	serverAddr := flag.String("server", "localhost:41234", "Server address")
	ipv6 := flag.Bool("6", false, "Use IPv6")
	keyPath := flag.String("key", "", "Path to Ed25519 operator private key (32-byte seed). Without this, runs as a passive agent.")
	keygenPath := flag.String("keygen", "", "Generate Ed25519 operator keypair at <path> (writes <path> and <path>.pub) and exit.")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(config.VersionInfo())
		os.Exit(0)
	}

	if *keygenPath != "" {
		if err := runKeygen(*keygenPath); err != nil {
			log.Fatalf("Keygen failed: %v", err)
		}
		return
	}

	var edPriv ed25519.PrivateKey
	if *keyPath != "" {
		k, err := auth.LoadPrivateKey(*keyPath)
		if err != nil {
			log.Fatalf("Load operator key: %v", err)
		}
		edPriv = k
	}

	client, err := NewClient(*serverAddr, *ipv6, edPriv)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nShutting down...")
		client.Shutdown()
	}()

	if err := client.Run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
