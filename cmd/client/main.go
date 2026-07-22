// HolePunch Client - Like ligolo-ng but with UDP hole punching
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"

	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/abb3rrant/HolePunch/pkg/auth"
	"github.com/abb3rrant/HolePunch/pkg/config"
	"github.com/abb3rrant/HolePunch/pkg/holepunch"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
	"github.com/abb3rrant/HolePunch/pkg/proxy"
)

// peerDeadTimeout is how long a peer may go without traffic before it is
// considered gone. Both sides send keepalives every KeepaliveTimeout, so this
// allows three missed keepalives before declaring the holepunch dead.
const peerDeadTimeout = 3 * holepunch.KeepaliveTimeout

type Client struct {
	// Transport layer. conn is the raw UDP socket shared by QUIC (for the
	// server signalling channel) and the hole puncher (for peer traffic).
	// quic.Transport.ReadNonQUICPacket surfaces peer packets that arrive on
	// the same UDP port as the QUIC connection to the server.
	conn net.PacketConn
	qt   *quic.Transport

	// Server signalling channel.  serverPipe is the write end of the POST
	// body piped to the server; serverResp is the server's response body;
	// serverRT is the HTTP/3 transport whose QUIC connection carries them.
	serverPipe *io.PipeWriter
	serverResp io.ReadCloser
	serverRT   *http3.Transport
	serverMu   sync.Mutex // serialises writes to serverPipe and channel swaps

	// Connection lifecycle.
	ctx          context.Context
	cancelCtx    context.CancelFunc
	shutdown     chan struct{}
	shutdownOnce sync.Once

	serverAddr string
	agentPath  string
	ignoreCert bool

	clientID [32]byte
	keys     *holepunch.KeyPair
	puncher  *holepunch.Puncher

	peers   map[string]*PeerEntry
	peersMu sync.RWMutex

	proxyManager *proxy.Manager
	stats        *config.Stats
	startTime    time.Time

	// Operator auth. edPrivKey is nil when no -key was passed.
	edPrivKey    ed25519.PrivateKey
	sessionNonce [32]byte

	// Tunnel state.
	stateMu       sync.RWMutex
	session       *PeerEntry
	tunnelStarted bool
	tunnelIface   string
	tunnelRoutes  []string
	tunFile       *os.File
	isOperator    bool

	// parked is true while an agent has gone dark: a holepunch is live, so the
	// orchestration-server channel is torn down until the last peer dies.
	parked bool

	// reconnecting is true while reconnectServerChannel is running, preventing
	// duplicate reconnect goroutines from racing each other.
	reconnecting bool

	// confirmingExit is set by the signal handler to coordinate a y/n prompt
	// with the interactive loop.
	confirmingExit atomic.Bool
}

type PeerEntry struct {
	ID        [32]byte
	PublicKey [32]byte
	Addr      *net.UDPAddr
	Connected bool
	Meta      *protocol.AgentMetadata
}

func NewClient(serverAddr, agentPath string, useIPv6 bool, edPrivKey ed25519.PrivateKey, ignoreCert bool) (*Client, error) {
	network := "udp4"
	if useIPv6 {
		network = "udp6"
	}

	udpConn, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	clientID, err := holepunch.GenerateClientID()
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	keys, err := holepunch.GenerateKeyPair()
	if err != nil {
		udpConn.Close()
		return nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())

	c := &Client{
		conn:       udpConn,
		qt:         &quic.Transport{Conn: udpConn},
		ctx:        ctx,
		cancelCtx:  cancelCtx,
		shutdown:   make(chan struct{}),
		serverAddr: serverAddr,
		agentPath:  agentPath,
		ignoreCert: ignoreCert,
		clientID:   clientID,
		keys:       keys,
		peers:      make(map[string]*PeerEntry),
		stats:      config.NewStats(),
		startTime:  time.Now(),
		edPrivKey:  edPrivKey,
	}

	c.puncher = holepunch.NewPuncher(udpConn, keys)
	c.puncher.SetDataHandler(c.onDataReceived)
	c.puncher.SetPeerConnectedHandler(c.onPeerConnected)
	c.puncher.SetPeerDisconnectedHandler(c.onPeerDisconnected)

	sendFunc := func(peerID [32]byte, data []byte) error {
		err := c.puncher.SendToPeer(peerID, data)
		if err == nil {
			c.stats.AddBytesSent(uint64(len(data)))
			c.stats.AddPacketsSent(1)
		}
		return err
	}
	c.proxyManager = proxy.NewManager(sendFunc)

	return c, nil
}

// connect dials the HTTP/3 signalling channel to the server.
// The underlying UDP socket is shared with the puncher, so the QUIC source
// port IS the hole-punch port the server records and shares with peers.
func (c *Client) connect() error {
	// Normalise server address to host:port.
	serverAddr := c.serverAddr
	if !strings.Contains(serverAddr, ":") {
		serverAddr += ":443"
	}
	serverURL := "https://" + serverAddr + c.agentPath

	tlsConf := &tls.Config{
		InsecureSkipVerify: c.ignoreCert, //nolint:gosec — intentional for self-signed mode
		NextProtos:         []string{"h3"},
	}

	qt := c.qt
	rt := &http3.Transport{
		TLSClientConfig: tlsConf,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}
			return qt.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		},
	}

	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(c.ctx, "POST", serverURL, pr)
	if err != nil {
		pr.Close()
		pw.Close()
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := rt.RoundTrip(req)
	if err != nil {
		pr.Close()
		pw.Close()
		return err
	}

	c.serverMu.Lock()
	c.serverPipe = pw
	c.serverResp = resp.Body
	c.serverRT = rt
	c.serverMu.Unlock()
	return nil
}

// sendToServer writes one complete protocol message to the server stream.
func (c *Client) sendToServer(data []byte) {
	c.serverMu.Lock()
	defer c.serverMu.Unlock()
	if c.serverPipe != nil {
		c.serverPipe.Write(data) //nolint:errcheck
	}
}

func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("PANIC in %s: %v", name, r)
			}
		}()
		fn()
	}()
}

func (c *Client) Run() error {
	log.Printf("Client ID: %s", hex.EncodeToString(c.clientID[:8]))
	log.Printf("Connecting to: %s", c.serverAddr)

	if err := c.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	if err := c.register(); err != nil {
		return fmt.Errorf("register failed: %w", err)
	}

	safeGo("serverReceiveLoop", c.serverReceiveLoop)
	safeGo("peerReceiveLoop", c.peerReceiveLoop)
	safeGo("keepaliveLoop", c.keepaliveLoop)
	safeGo("reaperLoop", c.reaperLoop)
	safeGo("interactiveMode", c.interactiveMode)

	<-c.shutdown
	return nil
}

func currentUsername() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func localIPAddresses() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var ips []string
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			ips = append(ips, ipnet.IP.String())
		}
	}
	return strings.Join(ips, ",")
}

func (c *Client) register() error {
	meta := &protocol.AgentMetadata{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		LocalIPs: localIPAddresses(),
	}
	if h, err := os.Hostname(); err == nil {
		meta.Hostname = h
	}
	meta.Username = currentUsername()

	msg := &protocol.RegisterMessage{ClientID: c.clientID, PublicKey: c.keys.PublicKey, Meta: meta}
	c.sendToServer(msg.Serialize())
	return nil
}

// serverReceiveLoop reads framed messages from the HTTP/3 response body. Each
// invocation binds to the response that was current when it started, so a
// reconnect can spin up a fresh loop without the old one interfering.
func (c *Client) serverReceiveLoop() {
	c.serverMu.Lock()
	resp := c.serverResp
	c.serverMu.Unlock()
	if resp == nil {
		return
	}

	for {
		data, err := readMsg(resp)
		if err != nil {
			// A deliberate park tears the channel down; exit quietly instead
			// of shutting the whole client down.
			if c.isParked() {
				return
			}
			select {
			case <-c.shutdown:
			default:
				log.Println("Server connection closed - reconnecting in background")
				go c.reconnectServerChannel()
			}
			return
		}
		c.stats.AddBytesReceived(uint64(len(data)))
		c.stats.AddPacketsReceived(1)
		c.handleServerMessage(data)
	}
}

// peerReceiveLoop reads raw (non-QUIC) UDP packets that arrive on the shared
// socket — these are encrypted hole-punch / data packets from peers.
func (c *Client) peerReceiveLoop() {
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.qt.ReadNonQUICPacket(c.ctx, buf)
		if err != nil {
			select {
			case <-c.shutdown:
			default:
				log.Printf("Peer read error: %v", err)
			}
			return
		}

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		c.stats.AddBytesReceived(uint64(n))
		c.stats.AddPacketsReceived(1)

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		c.puncher.HandlePacket(pkt, udpAddr)
	}
}

// readMsg reads one length-framed protocol message from r.
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

func (c *Client) handleServerMessage(data []byte) {
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
			log.Println("Operator authentication denied - continuing as agent")
		}

	case protocol.MsgTypePeerList:
		c.handlePeerList(payload)

	case protocol.MsgTypePunchInit:
		c.handlePunchInit(payload)
	}
}

func (c *Client) sendAuthRequest() {
	var pub [auth.PublicKeySize]byte
	copy(pub[:], c.edPrivKey.Public().(ed25519.PublicKey))

	sig := auth.Sign(c.edPrivKey, c.sessionNonce, c.clientID)
	msg := &protocol.AuthRequestMessage{PublicKey: pub, Signature: sig}
	c.sendToServer(msg.Serialize())
}

func (c *Client) operatorRole() bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.isOperator
}

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

		ipCopy := make(net.IP, ipLen)
		copy(ipCopy, data[offset:offset+ipLen])
		peer.Addr = &net.UDPAddr{
			IP:   ipCopy,
			Port: int(port),
		}
		offset += ipLen

		if offset+2 <= len(data) {
			metaLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2
			if metaLen > 0 && offset+metaLen <= len(data) {
				peer.Meta = protocol.ParseAgentMetadata(data[offset : offset+metaLen])
				offset += metaLen
			}
		}

		hexID := hex.EncodeToString(peer.ID[:8])
		if existing, exists := c.peers[hexID]; !exists {
			c.peers[hexID] = peer
			label := hexID
			if peer.Meta != nil && peer.Meta.Hostname != "" {
				label = peer.Meta.Hostname + " (" + hexID + ")"
			}
			log.Printf("Agent discovered: %s at %s", label, peer.Addr.String())
		} else {
			existing.Meta = peer.Meta
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

	// An agent goes dark once it has a live holepunch: the operator now reaches
	// it peer-to-peer, so there is no reason to keep beaconing to the server.
	// Operators stay connected so they can keep punching to other agents.
	if !c.operatorRole() {
		c.parkServerChannel()
	}
}

// onPeerDisconnected fires when a peer is reaped for inactivity. When an agent's
// last holepunch dies it reconnects to the orchestration server.
func (c *Client) onPeerDisconnected(peerID [32]byte) {
	hexID := hex.EncodeToString(peerID[:8])
	log.Printf("Agent disconnected (timed out): %s", hexID)

	c.peersMu.Lock()
	delete(c.peers, hexID)
	c.peersMu.Unlock()

	c.stateMu.Lock()
	if c.session != nil && c.session.ID == peerID {
		c.session = nil
	}
	c.stateMu.Unlock()

	if !c.operatorRole() && c.puncher.PeerCount() == 0 {
		c.unparkServerChannel()
	}
}

// isParked reports whether the agent is currently dark (no server channel).
func (c *Client) isParked() bool {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.parked
}

// parkServerChannel tears down the orchestration-server channel while a
// holepunch is live. No-op for operators or if already parked.
func (c *Client) parkServerChannel() {
	c.stateMu.Lock()
	if c.parked || c.isOperator {
		c.stateMu.Unlock()
		return
	}
	c.parked = true
	c.stateMu.Unlock()

	log.Println("Holepunch live - going dark from the orchestration server")
	c.closeServerChannel()
}

// unparkServerChannel re-establishes the orchestration-server channel after the
// last holepunch has died. No-op if not parked or shutting down.
func (c *Client) unparkServerChannel() {
	c.stateMu.Lock()
	if !c.parked {
		c.stateMu.Unlock()
		return
	}
	c.parked = false
	c.stateMu.Unlock()

	select {
	case <-c.shutdown:
		return
	default:
	}

	log.Println("Holepunch died - reconnecting to the orchestration server")
	go c.reconnectServerChannel()
}

// reconnectServerChannel re-establishes the orchestration-server channel with
// exponential back-off.  It guards against concurrent invocations so at most
// one reconnect loop is running at any time.  Peer traffic is unaffected while
// this runs: the UDP socket and puncher continue operating normally.
func (c *Client) reconnectServerChannel() {
	c.stateMu.Lock()
	if c.reconnecting {
		c.stateMu.Unlock()
		return
	}
	c.reconnecting = true
	c.stateMu.Unlock()
	defer func() {
		c.stateMu.Lock()
		c.reconnecting = false
		c.stateMu.Unlock()
	}()

	const maxDelay = 60 * time.Second
	delay := time.Duration(0) // first attempt is immediate
	for {
		select {
		case <-c.shutdown:
			return
		case <-time.After(delay):
		}
		if c.isParked() {
			return // got parked while waiting; unparkServerChannel will reconnect
		}
		if err := c.connect(); err != nil {
			if delay == 0 {
				delay = 5 * time.Second
			} else {
				delay = min(delay*2, maxDelay)
			}
			continue
		}
		if err := c.register(); err != nil {
			delay = 5 * time.Second
			continue
		}
		log.Println("Reconnected to orchestration server")
		safeGo("serverReceiveLoop", c.serverReceiveLoop)
		return
	}
}

// closeServerChannel tears down the current server channel (pipe, response,
// and the HTTP/3 transport's QUIC connection) without touching the shared UDP
// socket or quic.Transport, so peer traffic and the NAT mapping survive.
func (c *Client) closeServerChannel() {
	c.serverMu.Lock()
	pipe := c.serverPipe
	resp := c.serverResp
	rt := c.serverRT
	c.serverPipe = nil
	c.serverResp = nil
	c.serverRT = nil
	c.serverMu.Unlock()

	if pipe != nil {
		pipe.Close()
	}
	if resp != nil {
		resp.Close()
	}
	if rt != nil {
		rt.Close()
	}
}

// reaperLoop periodically expires peers that have gone silent, which is how a
// dead holepunch is detected.
func (c *Client) reaperLoop() {
	ticker := time.NewTicker(holepunch.KeepaliveTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-c.shutdown:
			return
		case <-ticker.C:
			c.puncher.ReapStalePeers(peerDeadTimeout)
		}
	}
}

func (c *Client) keepaliveLoop() {
	ticker := time.NewTicker(holepunch.KeepaliveTimeout)
	defer ticker.Stop()

	keepalive := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeKeepalive, Length: 0}
	keepaliveData := keepalive.Serialize()

	for {
		select {
		case <-c.shutdown:
			return
		case <-ticker.C:
			// Peer keepalives must keep flowing even while parked — they hold
			// the holepunch (and its NAT mapping) open. Server keepalives stop
			// while parked since the channel is gone.
			if !c.isParked() {
				c.sendToServer(keepaliveData)
			}
			c.puncher.SendKeepalive()
		}
	}
}

func (c *Client) interactiveMode() {
	scanner := bufio.NewScanner(os.Stdin)
	c.printBanner()

	tty := config.StdinIsTTY()

	if tty {
		fmt.Print(config.Prompt)
	}
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if c.confirmingExit.CompareAndSwap(true, false) {
			lower := strings.ToLower(line)
			if lower == "y" || lower == "yes" {
				c.Shutdown()
				return
			}
			fmt.Println("Exit cancelled.")
			if tty {
				fmt.Print(config.Prompt)
			}
			continue
		}

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
		metaStr := ""
		if peer.Meta != nil {
			var parts []string
			if peer.Meta.Hostname != "" {
				parts = append(parts, peer.Meta.Hostname)
			}
			if peer.Meta.Username != "" {
				parts = append(parts, peer.Meta.Username)
			}
			if peer.Meta.OS != "" {
				osInfo := peer.Meta.OS
				if peer.Meta.Arch != "" {
					osInfo += "/" + peer.Meta.Arch
				}
				parts = append(parts, osInfo)
			}
			if peer.Meta.LocalIPs != "" {
				parts = append(parts, peer.Meta.LocalIPs)
			}
			if len(parts) > 0 {
				metaStr = " [" + strings.Join(parts, ", ") + "]"
			}
		}
		fmt.Printf("  %s - %s (%s)%s%s\n", hexID, peer.Addr.String(), status, metaStr, selected)
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
		c.sendToServer(msg)
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

	c.proxyManager.SetTUNWriter(c.tunWritePacket)
	safeGo("tunReadLoop", c.tunReadLoop)

	fmt.Printf("Tunnel %s is up\n", iface)
	fmt.Println("Add routes: route add <cidr>")
}

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

		ipPacket := buf[:n]
		version := ipPacket[0] >> 4
		if version != 4 {
			continue
		}

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

		ipCopy := make([]byte, n)
		copy(ipCopy, ipPacket)

		if err := c.proxyManager.SendIPPacket(targetPeerID, ipCopy); err != nil {
			log.Printf("TUN: failed to send IP packet: %v", err)
		}
	}
}

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
	c.stateMu.RLock()
	started := c.tunnelStarted
	session := c.session
	iface := c.tunnelIface
	c.stateMu.RUnlock()

	if !started {
		fmt.Println("Start tunnel first")
		return
	}

	if session == nil {
		fmt.Println("No session")
		return
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Invalid CIDR: %s\n", cidr)
		return
	}

	if err := c.puncher.AddAllowedIP(session.ID, *ipnet); err != nil {
		fmt.Printf("Failed to add allowed IP: %v\n", err)
		return
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "add", cidr, "dev", iface)
	case "darwin":
		cmd = exec.Command("route", "-n", "add", "-net", cidr, "240.0.0.1")
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exist") {
			fmt.Printf("Failed: %v: %s\n", err, out)
			return
		}
	}

	c.stateMu.Lock()
	c.tunnelRoutes = append(c.tunnelRoutes, cidr)
	c.stateMu.Unlock()
	fmt.Printf("Route added: %s (AllowedIP for peer)\n", cidr)
}

func (c *Client) delRoute(cidr string) {
	_, ipnet, _ := net.ParseCIDR(cidr)

	c.stateMu.RLock()
	session := c.session
	c.stateMu.RUnlock()

	if session != nil && ipnet != nil {
		c.puncher.RemoveAllowedIP(session.ID, *ipnet)
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "del", cidr)
	case "darwin":
		cmd = exec.Command("route", "-n", "delete", "-net", cidr)
	}
	cmd.Run()

	c.stateMu.Lock()
	var newRoutes []string
	for _, r := range c.tunnelRoutes {
		if r != cidr {
			newRoutes = append(newRoutes, r)
		}
	}
	c.tunnelRoutes = newRoutes
	c.stateMu.Unlock()
	fmt.Printf("Route removed: %s\n", cidr)
}

func (c *Client) listRoutes() {
	c.stateMu.RLock()
	routes := make([]string, len(c.tunnelRoutes))
	copy(routes, c.tunnelRoutes)
	session := c.session
	c.stateMu.RUnlock()

	if len(routes) == 0 {
		fmt.Println("No routes")
		return
	}
	fmt.Println("Routes (AllowedIPs):")
	for _, r := range routes {
		peerInfo := ""
		if session != nil {
			peerInfo = fmt.Sprintf(" -> peer %s", hex.EncodeToString(session.ID[:4]))
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

func (c *Client) requestExitConfirmation() {
	c.stateMu.RLock()
	tunnelUp := c.tunnelStarted
	hasSession := c.session != nil
	c.stateMu.RUnlock()

	warning := ""
	if tunnelUp {
		warning = " Active tunnel will be torn down."
	} else if hasSession {
		warning = " Active session will be closed."
	}
	fmt.Printf("\nAre you sure you want to exit?%s (y/N): ", warning)
	c.confirmingExit.Store(true)
}

func (c *Client) Shutdown() {
	c.shutdownOnce.Do(func() {
		if c.tunnelStarted {
			c.stopTunnel()
		}
		if c.proxyManager != nil {
			c.proxyManager.Close()
		}
		disconn := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeDisconnect, Length: 0}
		c.sendToServer(disconn.Serialize())
		c.closeServerChannel()
		c.cancelCtx()
		close(c.shutdown)
		c.conn.Close()
	})
}

func runKeygen(path string) error {
	for _, p := range []string{path, path + ".pub"} {
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s already exists - refusing to overwrite", p)
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
	// quic-go prints a warning when the kernel UDP buffer is below its ideal
	// size. On WSL2 and hardened Linux systems this is unavoidable without root.
	// The smaller buffer has no measurable impact for a VPN tool, so silence it.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "1") //nolint:errcheck

	serverAddr := flag.String("server", fmt.Sprintf("localhost:%d", config.DefaultServerPort), "Server address (host:port)")
	agentPath := flag.String("agent-path", "/v1/metrics", "HTTP path for agent connection (must match server -agent-path)")
	ipv6 := flag.Bool("6", false, "Use IPv6")
	keyPath := flag.String("key", "", "Path to Ed25519 operator private key. Without this, runs as a passive agent.")
	keygenPath := flag.String("keygen", "", "Generate Ed25519 operator keypair at <path> and exit.")
	ignoreCert := flag.Bool("ignorecert", false, "Skip TLS certificate verification (required when server uses -tls-mode self)")
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

	client, err := NewClient(*serverAddr, *agentPath, *ipv6, edPriv, *ignoreCert)
	if err != nil {
		log.Fatalf("Failed: %v", err)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	isInteractiveOperator := edPriv != nil && config.StdinIsTTY()
	go func() {
		sig := <-sigCh
		if sig == syscall.SIGTERM || !isInteractiveOperator {
			fmt.Println("\nShutting down...")
			go func() {
				<-sigCh
				fmt.Println("\nForce quit.")
				os.Exit(1)
			}()
			client.Shutdown()
			return
		}
		client.requestExitConfirmation()
		<-sigCh
		fmt.Println("\nForce quit.")
		os.Exit(1)
	}()

	if err := client.Run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
