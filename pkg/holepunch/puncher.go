package holepunch

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// PeerConnection represents an established peer-to-peer connection ()
type PeerConnection struct {
	PeerID     [32]byte
	PublicKey  [32]byte
	Addr       *net.UDPAddr
	Encryptor  *Encryptor
	LastSeen   time.Time
	AllowedIPs []net.IPNet // cryptokey routing
	mu         sync.RWMutex
}

// Puncher handles UDP hole punching with connection behavior
type Puncher struct {
	conn         net.PacketConn
	localKeys    *KeyPair
	peers        map[[32]byte]*PeerConnection
	pubKeyToPeer map[[32]byte][32]byte // PublicKey -> PeerID mapping
	addrToPeer   map[string][32]byte   // "IP:Port" -> PeerID mapping
	ipToPeer     map[string][32]byte   // Tunnel IP -> PeerID (cryptokey routing)
	peersMu      sync.RWMutex
	onData       func(peerID [32]byte, data []byte)
	onPeerConn   func(peerID [32]byte)
	silentMode   bool // : don't respond to unknown sources
}

// NewPuncher creates a new hole puncher with connection handling
func NewPuncher(conn net.PacketConn, keys *KeyPair) *Puncher {
	return &Puncher{
		conn:         conn,
		localKeys:    keys,
		peers:        make(map[[32]byte]*PeerConnection),
		pubKeyToPeer: make(map[[32]byte][32]byte),
		addrToPeer:   make(map[string][32]byte),
		ipToPeer:     make(map[string][32]byte),
		silentMode:   true, // : silent by default
	}
}

// SetSilentMode enables/disables silent mode
func (p *Puncher) SetSilentMode(silent bool) {
	p.peersMu.Lock()
	defer p.peersMu.Unlock()
	p.silentMode = silent
}

// SetDataHandler sets the callback for received data
func (p *Puncher) SetDataHandler(handler func(peerID [32]byte, data []byte)) {
	p.onData = handler
}

// SetPeerConnectedHandler sets the callback for new peer connections
func (p *Puncher) SetPeerConnectedHandler(handler func(peerID [32]byte)) {
	p.onPeerConn = handler
}

// InitiatePunch starts hole punching to a peer with optional AllowedIPs
func (p *Puncher) InitiatePunch(peerID [32]byte, peerPublicKey [32]byte, peerAddr *net.UDPAddr) error {
	return p.InitiatePunchWithAllowedIPs(peerID, peerPublicKey, peerAddr, nil)
}

// InitiatePunchWithAllowedIPs starts hole punching with cryptokey routing
func (p *Puncher) InitiatePunchWithAllowedIPs(peerID [32]byte, peerPublicKey [32]byte, peerAddr *net.UDPAddr, allowedIPs []net.IPNet) error {
	// Compute shared secret
	sharedSecret, err := ComputeSharedSecret(&p.localKeys.PrivateKey, &peerPublicKey)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptor, err := NewEncryptor(sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to create encryptor: %w", err)
	}

	peer := &PeerConnection{
		PeerID:     peerID,
		PublicKey:  peerPublicKey,
		Addr:       peerAddr,
		Encryptor:  encryptor,
		LastSeen:   time.Now(),
		AllowedIPs: allowedIPs,
	}

	p.peersMu.Lock()
	p.peers[peerID] = peer
	p.pubKeyToPeer[peerPublicKey] = peerID
	p.addrToPeer[peerAddr.String()] = peerID

	// Register AllowedIPs for cryptokey routing
	for _, ipnet := range allowedIPs {
		p.ipToPeer[ipnet.String()] = peerID
	}
	p.peersMu.Unlock()

	// Send punch packets (multiple for reliability)
	keyExMsg := &protocol.KeyExchangeMessage{PublicKey: p.localKeys.PublicKey}
	punchData := keyExMsg.Serialize()

	for i := 0; i < 5; i++ {
		_, err := p.conn.WriteTo(punchData, peerAddr)
		if err != nil {
			return fmt.Errorf("failed to send punch packet: %w", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	return nil
}

// HandlePacket processes an incoming packet from a peer
func (p *Puncher) HandlePacket(data []byte, addr *net.UDPAddr) error {
	if len(data) < protocol.HeaderSize {
		return fmt.Errorf("packet too small")
	}

	header, err := protocol.ParseHeader(data)
	if err != nil {
		return err
	}

	payload := data[protocol.HeaderSize:]

	switch header.Type {
	case protocol.MsgTypeKeyExchange:
		return p.handleKeyExchange(payload, addr)
	case protocol.MsgTypeData:
		return p.handleData(payload, addr)
	case protocol.MsgTypeKeepalive:
		return p.handleKeepalive(addr)
	}

	return nil
}

func (p *Puncher) handleKeyExchange(data []byte, addr *net.UDPAddr) error {
	msg, err := protocol.ParseKeyExchangeMessage(data)
	if err != nil {
		return err
	}

	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	// Check if we know this peer by public key or address
	var peerID [32]byte
	var peer *PeerConnection
	var exists bool

	// First try to find by public key (: authenticate by key first)
	if knownID, ok := p.pubKeyToPeer[msg.PublicKey]; ok {
		peerID = knownID
		peer, exists = p.peers[peerID]
	}

	// Then try by address
	if !exists {
		if knownID, ok := p.addrToPeer[addr.String()]; ok {
			peerID = knownID
			peer, exists = p.peers[peerID]
		}
	}

	if !exists {
		// silent mode: don't respond to unknown peers
		if p.silentMode {
			return nil // Silent drop
		}

		// New peer we don't know about - use public key as ID
		copy(peerID[:], msg.PublicKey[:])

		sharedSecret, err := ComputeSharedSecret(&p.localKeys.PrivateKey, &msg.PublicKey)
		if err != nil {
			return err
		}

		encryptor, err := NewEncryptor(sharedSecret)
		if err != nil {
			return err
		}

		peer = &PeerConnection{
			PeerID:    peerID,
			PublicKey: msg.PublicKey,
			Addr:      addr,
			Encryptor: encryptor,
			LastSeen:  time.Now(),
		}
		p.peers[peerID] = peer
		p.pubKeyToPeer[msg.PublicKey] = peerID
		p.addrToPeer[addr.String()] = peerID

		// Send our public key back
		keyExMsg := &protocol.KeyExchangeMessage{PublicKey: p.localKeys.PublicKey}
		p.conn.WriteTo(keyExMsg.Serialize(), addr)

		if p.onPeerConn != nil {
			go p.onPeerConn(peerID)
		}
	} else {
		// Already-authenticated peer. Check whether this is a genuine roam
		// (source address changed) before replying — otherwise every received
		// KE would trigger a KE response, creating an infinite ping-pong.
		peer.mu.Lock()
		oldAddr := peer.Addr.String()
		addrChanged := oldAddr != addr.String()
		peer.Addr = addr
		peer.LastSeen = time.Now()
		peer.mu.Unlock()

		p.pubKeyToPeer[msg.PublicKey] = peerID

		if addrChanged {
			delete(p.addrToPeer, oldAddr)
			p.addrToPeer[addr.String()] = peerID
			// Acknowledge the new endpoint with a single KE. The peer's
			// own roam-check will see no further address change and stop.
			keyExMsg := &protocol.KeyExchangeMessage{PublicKey: p.localKeys.PublicKey}
			p.conn.WriteTo(keyExMsg.Serialize(), addr)
		}
	}

	return nil
}

func (p *Puncher) handleData(data []byte, addr *net.UDPAddr) error {
	msg, err := protocol.ParseDataMessage(data)
	if err != nil {
		return err
	}

	// Find peer by address using our mapping
	p.peersMu.RLock()
	peerID, ok := p.addrToPeer[addr.String()]
	var peer *PeerConnection
	if ok {
		peer = p.peers[peerID]
	}
	p.peersMu.RUnlock()

	if peer == nil {
		// : silently drop data from unknown sources
		return nil
	}

	plaintext, err := peer.Encryptor.Decrypt(msg.Nonce, msg.Ciphertext)
	if err != nil {
		// : silently drop packets that fail authentication
		return nil
	}

	// Roaming: update endpoint on successful decryption.
	//
	// Locks are NOT nested: we touch peer.mu and peersMu in separate
	// critical sections, in that order. Everywhere else in this package
	// the order is peersMu → peer.mu, so nesting them in the reverse
	// order here would risk deadlock against e.g. AddAllowedIP or
	// handleKeyExchange running concurrently.
	peer.mu.Lock()
	oldAddrStr := peer.Addr.String()
	roamed := oldAddrStr != addr.String()
	if roamed {
		peer.Addr = addr
	}
	peer.LastSeen = time.Now()
	peer.mu.Unlock()

	if roamed {
		p.peersMu.Lock()
		delete(p.addrToPeer, oldAddrStr)
		p.addrToPeer[addr.String()] = peer.PeerID
		p.peersMu.Unlock()
	}

	if p.onData != nil {
		p.onData(peer.PeerID, plaintext)
	}

	return nil
}

func (p *Puncher) handleKeepalive(addr *net.UDPAddr) error {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	if peerID, ok := p.addrToPeer[addr.String()]; ok {
		if peer, exists := p.peers[peerID]; exists {
			peer.mu.Lock()
			peer.LastSeen = time.Now()
			peer.mu.Unlock()
		}
	}

	return nil
}

// SendToPeer sends encrypted data to a peer
func (p *Puncher) SendToPeer(peerID [32]byte, data []byte) error {
	p.peersMu.RLock()
	peer, exists := p.peers[peerID]
	p.peersMu.RUnlock()

	if !exists {
		return fmt.Errorf("peer not found")
	}

	nonce, ciphertext, err := peer.Encryptor.Encrypt(data)
	if err != nil {
		return err
	}

	msg := &protocol.DataMessage{
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}

	_, err = p.conn.WriteTo(msg.Serialize(), peer.Addr)
	return err
}

// SendKeepalive sends keepalive to all peers
func (p *Puncher) SendKeepalive() {
	keepalive := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeKeepalive, Length: 0}
	data := keepalive.Serialize()

	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	for _, peer := range p.peers {
		p.conn.WriteTo(data, peer.Addr)
	}
}

// GetPeers returns a list of connected peer IDs
func (p *Puncher) GetPeers() [][32]byte {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	var peers [][32]byte
	for id := range p.peers {
		peers = append(peers, id)
	}
	return peers
}

// AddAllowedIP adds an AllowedIP to a peer (cryptokey routing)
func (p *Puncher) AddAllowedIP(peerID [32]byte, ipnet net.IPNet) error {
	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	peer, exists := p.peers[peerID]
	if !exists {
		return fmt.Errorf("peer not found")
	}

	peer.mu.Lock()
	peer.AllowedIPs = append(peer.AllowedIPs, ipnet)
	peer.mu.Unlock()

	p.ipToPeer[ipnet.String()] = peerID
	return nil
}

// RemoveAllowedIP removes an AllowedIP from a peer
func (p *Puncher) RemoveAllowedIP(peerID [32]byte, ipnet net.IPNet) {
	p.peersMu.Lock()
	defer p.peersMu.Unlock()

	peer, exists := p.peers[peerID]
	if !exists {
		return
	}

	peer.mu.Lock()
	var newAllowed []net.IPNet
	for _, ip := range peer.AllowedIPs {
		if ip.String() != ipnet.String() {
			newAllowed = append(newAllowed, ip)
		}
	}
	peer.AllowedIPs = newAllowed
	peer.mu.Unlock()

	delete(p.ipToPeer, ipnet.String())
}

// LookupPeerByIP finds peer by destination IP (cryptokey routing)
func (p *Puncher) LookupPeerByIP(ip net.IP) (*PeerConnection, bool) {
	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	for _, peer := range p.peers {
		peer.mu.RLock()
		for _, allowed := range peer.AllowedIPs {
			if allowed.Contains(ip) {
				peer.mu.RUnlock()
				return peer, true
			}
		}
		peer.mu.RUnlock()
	}
	return nil, false
}

// SendToIP sends data to the peer that owns the destination IP ()
func (p *Puncher) SendToIP(dstIP net.IP, data []byte) error {
	peer, found := p.LookupPeerByIP(dstIP)
	if !found {
		return fmt.Errorf("no peer for IP: %s", dstIP)
	}
	return p.SendToPeer(peer.PeerID, data)
}

// GetPeerAllowedIPs returns the AllowedIPs for a peer
func (p *Puncher) GetPeerAllowedIPs(peerID [32]byte) []net.IPNet {
	p.peersMu.RLock()
	peer, exists := p.peers[peerID]
	p.peersMu.RUnlock()

	if !exists {
		return nil
	}

	peer.mu.RLock()
	defer peer.mu.RUnlock()
	result := make([]net.IPNet, len(peer.AllowedIPs))
	copy(result, peer.AllowedIPs)
	return result
}
