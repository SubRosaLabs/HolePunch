package holepunch

import (
	"net"
	"testing"
)

// Edge case tests for VPN routing scenarios

func TestEdgeCase_RouteToAgentOwnIP(t *testing.T) {
	// Edge case: What if agent's own IP is in the route?
	// e.g., agent is 192.168.1.50, you add route 192.168.1.0/24
	// Packets TO the agent should still work

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		PublicKey: peerKeys.PublicKey,
		Addr:      &net.UDPAddr{IP: net.ParseIP("192.168.1.50"), Port: 12345}, // Agent's own IP
		Encryptor: enc,
	}
	p.peersMu.Unlock()

	// Add entire /24 as AllowedIP
	_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
	p.AddAllowedIP(peerID, *ipnet)

	// Packets to ANY host in 192.168.1.0/24 should route to this peer
	// Including the agent itself (for local services) and other hosts
	testIPs := []string{
		"192.168.1.1",   // Gateway
		"192.168.1.10",  // Some server
		"192.168.1.50",  // Agent itself
		"192.168.1.100", // Another host
	}

	for _, ip := range testIPs {
		_, found := p.LookupPeerByIP(net.ParseIP(ip))
		if !found {
			t.Errorf("Should route %s to peer", ip)
		}
	}
}

func TestEdgeCase_OverlappingRoutes(t *testing.T) {
	// Edge case: Overlapping CIDR ranges
	// What if you add both 10.0.0.0/8 and 10.0.1.0/24?

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		Encryptor: enc,
	}
	p.peersMu.Unlock()

	// Add overlapping routes
	_, ipnet1, _ := net.ParseCIDR("10.0.0.0/8")
	_, ipnet2, _ := net.ParseCIDR("10.0.1.0/24")

	p.AddAllowedIP(peerID, *ipnet1)
	p.AddAllowedIP(peerID, *ipnet2)

	// Both should match 10.0.1.50
	_, found := p.LookupPeerByIP(net.ParseIP("10.0.1.50"))
	if !found {
		t.Error("Should find peer for overlapping route")
	}
}

func TestEdgeCase_NoRouteNoSession(t *testing.T) {
	// Edge case: No AllowedIP match and no session fallback
	// This is handled in tunReadLoop - packet should be dropped

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// No peers, no routes
	_, found := p.LookupPeerByIP(net.ParseIP("10.0.0.1"))
	if found {
		t.Error("Should not find peer when no routes exist")
	}
}

func TestEdgeCase_IPv6Ignored(t *testing.T) {
	// Edge case: IPv6 addresses should not match IPv4 routes
	// The code only supports IPv4 currently

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		Encryptor: enc,
	}
	p.peersMu.Unlock()

	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	p.AddAllowedIP(peerID, *ipnet)

	// IPv6 address should not match
	_, found := p.LookupPeerByIP(net.ParseIP("::1"))
	if found {
		t.Error("IPv6 should not match IPv4 route")
	}

	// But IPv4 should work
	_, found = p.LookupPeerByIP(net.ParseIP("10.0.0.1"))
	if !found {
		t.Error("IPv4 should match")
	}
}

func TestEdgeCase_BroadcastAddress(t *testing.T) {
	// Edge case: Broadcast addresses (e.g., 192.168.1.255 for /24)

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		Encryptor: enc,
	}
	p.peersMu.Unlock()

	_, ipnet, _ := net.ParseCIDR("192.168.1.0/24")
	p.AddAllowedIP(peerID, *ipnet)

	// Broadcast address is within CIDR
	_, found := p.LookupPeerByIP(net.ParseIP("192.168.1.255"))
	if !found {
		t.Error("Broadcast address should be in route")
	}

	// Network address too
	_, found = p.LookupPeerByIP(net.ParseIP("192.168.1.0"))
	if !found {
		t.Error("Network address should be in route")
	}
}

func TestEdgeCase_SingleHostRoute(t *testing.T) {
	// Edge case: /32 route for a single host

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		Encryptor: enc,
	}
	p.peersMu.Unlock()

	// Single host route
	_, ipnet, _ := net.ParseCIDR("10.0.0.50/32")
	p.AddAllowedIP(peerID, *ipnet)

	// Should match exact IP only
	_, found := p.LookupPeerByIP(net.ParseIP("10.0.0.50"))
	if !found {
		t.Error("Should match exact /32 host")
	}

	// Should NOT match neighbors
	_, found = p.LookupPeerByIP(net.ParseIP("10.0.0.49"))
	if found {
		t.Error("Should not match neighbor with /32")
	}

	_, found = p.LookupPeerByIP(net.ParseIP("10.0.0.51"))
	if found {
		t.Error("Should not match neighbor with /32")
	}
}

func TestEdgeCase_DefaultRoute(t *testing.T) {
	// Edge case: 0.0.0.0/0 route (route all traffic)

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		Encryptor: enc,
	}
	p.peersMu.Unlock()

	// Default route
	_, ipnet, _ := net.ParseCIDR("0.0.0.0/0")
	p.AddAllowedIP(peerID, *ipnet)

	// Should match everything
	testIPs := []string{
		"10.0.0.1",
		"192.168.1.1",
		"8.8.8.8",
		"1.1.1.1",
		"172.16.0.1",
	}

	for _, ip := range testIPs {
		_, found := p.LookupPeerByIP(net.ParseIP(ip))
		if !found {
			t.Errorf("0.0.0.0/0 should match %s", ip)
		}
	}
}

func TestEdgeCase_MultiplePeersSameSubnet(t *testing.T) {
	// Edge case: Two peers claim the same subnet
	// First one registered wins (undefined behavior - user error)

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peer1Keys, _ := GenerateKeyPair()
	peer2Keys, _ := GenerateKeyPair()

	var peer1ID, peer2ID [32]byte
	copy(peer1ID[:], peer1Keys.PublicKey[:])
	copy(peer2ID[:], peer2Keys.PublicKey[:])

	secret1, _ := ComputeSharedSecret(&keys.PrivateKey, &peer1Keys.PublicKey)
	secret2, _ := ComputeSharedSecret(&keys.PrivateKey, &peer2Keys.PublicKey)
	enc1, _ := NewEncryptor(secret1)
	enc2, _ := NewEncryptor(secret2)

	p.peersMu.Lock()
	p.peers[peer1ID] = &PeerConnection{PeerID: peer1ID, Encryptor: enc1}
	p.peers[peer2ID] = &PeerConnection{PeerID: peer2ID, Encryptor: enc2}
	p.peersMu.Unlock()

	// Both claim same subnet (user configuration error)
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peer1ID, *ipnet)
	p.AddAllowedIP(peer2ID, *ipnet) // This overwrites in ipToPeer map

	// Should still find A peer (behavior is map-dependent)
	_, found := p.LookupPeerByIP(net.ParseIP("10.0.0.1"))
	if !found {
		t.Error("Should find at least one peer")
	}
}
