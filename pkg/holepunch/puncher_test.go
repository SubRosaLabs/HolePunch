package holepunch

import (
	"net"
	"testing"
)

func TestAddAllowedIP(t *testing.T) {
	// Create a mock UDP connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP socket: %v", err)
	}
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Create a peer
	peerKeys, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	// Disable silent mode for this test
	p.SetSilentMode(false)

	// Add peer manually
	sharedSecret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	encryptor, _ := NewEncryptor(sharedSecret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		PublicKey: peerKeys.PublicKey,
		Addr:      peerAddr,
		Encryptor: encryptor,
	}
	p.peersMu.Unlock()

	// Add AllowedIP
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	err = p.AddAllowedIP(peerID, *ipnet)
	if err != nil {
		t.Fatalf("AddAllowedIP failed: %v", err)
	}

	// Verify AllowedIP was added
	allowedIPs := p.GetPeerAllowedIPs(peerID)
	if len(allowedIPs) != 1 {
		t.Fatalf("Expected 1 AllowedIP, got %d", len(allowedIPs))
	}
	if allowedIPs[0].String() != "10.0.0.0/24" {
		t.Errorf("Wrong AllowedIP: got %s, want 10.0.0.0/24", allowedIPs[0].String())
	}
}

func TestLookupPeerByIP(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Create peer
	peerKeys, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	sharedSecret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	encryptor, _ := NewEncryptor(sharedSecret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		PublicKey: peerKeys.PublicKey,
		Addr:      peerAddr,
		Encryptor: encryptor,
	}
	p.peersMu.Unlock()

	// Add AllowedIP for 10.0.0.0/24
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peerID, *ipnet)

	// Lookup IP within the allowed range
	testIP := net.ParseIP("10.0.0.50")
	foundPeer, found := p.LookupPeerByIP(testIP)
	if !found {
		t.Fatal("LookupPeerByIP should find peer for 10.0.0.50")
	}
	if foundPeer.PeerID != peerID {
		t.Error("Found wrong peer")
	}

	// Lookup IP outside the allowed range
	outsideIP := net.ParseIP("192.168.1.50")
	_, found = p.LookupPeerByIP(outsideIP)
	if found {
		t.Error("LookupPeerByIP should not find peer for 192.168.1.50")
	}
}

func TestLookupPeerByIPMultipleRanges(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Create peer
	peerKeys, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	sharedSecret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	encryptor, _ := NewEncryptor(sharedSecret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		PublicKey: peerKeys.PublicKey,
		Addr:      peerAddr,
		Encryptor: encryptor,
	}
	p.peersMu.Unlock()

	// Add multiple AllowedIPs
	_, ipnet1, _ := net.ParseCIDR("10.0.0.0/24")
	_, ipnet2, _ := net.ParseCIDR("172.16.0.0/16")
	_, ipnet3, _ := net.ParseCIDR("192.168.100.0/24")

	p.AddAllowedIP(peerID, *ipnet1)
	p.AddAllowedIP(peerID, *ipnet2)
	p.AddAllowedIP(peerID, *ipnet3)

	// Test all ranges
	testCases := []struct {
		ip    string
		found bool
	}{
		{"10.0.0.1", true},
		{"10.0.0.254", true},
		{"172.16.5.10", true},
		{"172.16.255.255", true},
		{"192.168.100.50", true},
		{"192.168.1.1", false}, // Not in allowed ranges
		{"8.8.8.8", false},     // External
		{"10.1.0.1", false},    // Different /24
	}

	for _, tc := range testCases {
		ip := net.ParseIP(tc.ip)
		_, found := p.LookupPeerByIP(ip)
		if found != tc.found {
			t.Errorf("LookupPeerByIP(%s): got %v, want %v", tc.ip, found, tc.found)
		}
	}
}

func TestRemoveAllowedIP(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Create peer
	peerKeys, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	sharedSecret, _ := ComputeSharedSecret(&keys.PrivateKey, &peerKeys.PublicKey)
	encryptor, _ := NewEncryptor(sharedSecret)

	p.peersMu.Lock()
	p.peers[peerID] = &PeerConnection{
		PeerID:    peerID,
		PublicKey: peerKeys.PublicKey,
		Addr:      peerAddr,
		Encryptor: encryptor,
	}
	p.peersMu.Unlock()

	// Add AllowedIPs
	_, ipnet1, _ := net.ParseCIDR("10.0.0.0/24")
	_, ipnet2, _ := net.ParseCIDR("172.16.0.0/16")

	p.AddAllowedIP(peerID, *ipnet1)
	p.AddAllowedIP(peerID, *ipnet2)

	// Verify both exist
	if len(p.GetPeerAllowedIPs(peerID)) != 2 {
		t.Fatal("Should have 2 AllowedIPs")
	}

	// Remove one
	p.RemoveAllowedIP(peerID, *ipnet1)

	// Verify only one remains
	allowedIPs := p.GetPeerAllowedIPs(peerID)
	if len(allowedIPs) != 1 {
		t.Fatalf("Should have 1 AllowedIP after removal, got %d", len(allowedIPs))
	}
	if allowedIPs[0].String() != "172.16.0.0/16" {
		t.Errorf("Wrong AllowedIP remaining: %s", allowedIPs[0].String())
	}

	// Lookup should fail for removed range
	_, found := p.LookupPeerByIP(net.ParseIP("10.0.0.1"))
	if found {
		t.Error("Should not find peer for removed AllowedIP")
	}

	// Lookup should succeed for remaining range
	_, found = p.LookupPeerByIP(net.ParseIP("172.16.1.1"))
	if !found {
		t.Error("Should find peer for remaining AllowedIP")
	}
}

func TestSilentMode(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Silent mode is on by default
	if !p.silentMode {
		t.Error("Silent mode should be on by default")
	}

	// Disable it
	p.SetSilentMode(false)
	if p.silentMode {
		t.Error("Silent mode should be off after SetSilentMode(false)")
	}

	// Enable it
	p.SetSilentMode(true)
	if !p.silentMode {
		t.Error("Silent mode should be on after SetSilentMode(true)")
	}
}

func TestMultiplePeersRouting(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Create two peers with different AllowedIPs
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
	p.peers[peer1ID] = &PeerConnection{
		PeerID:    peer1ID,
		PublicKey: peer1Keys.PublicKey,
		Addr:      &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 1111},
		Encryptor: enc1,
	}
	p.peers[peer2ID] = &PeerConnection{
		PeerID:    peer2ID,
		PublicKey: peer2Keys.PublicKey,
		Addr:      &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 2222},
		Encryptor: enc2,
	}
	p.peersMu.Unlock()

	// Peer 1 handles 10.0.0.0/24
	_, ipnet1, _ := net.ParseCIDR("10.0.0.0/24")
	p.AddAllowedIP(peer1ID, *ipnet1)

	// Peer 2 handles 192.168.0.0/16
	_, ipnet2, _ := net.ParseCIDR("192.168.0.0/16")
	p.AddAllowedIP(peer2ID, *ipnet2)

	// Test routing
	foundPeer, found := p.LookupPeerByIP(net.ParseIP("10.0.0.50"))
	if !found || foundPeer.PeerID != peer1ID {
		t.Error("10.0.0.50 should route to peer 1")
	}

	foundPeer, found = p.LookupPeerByIP(net.ParseIP("192.168.1.100"))
	if !found || foundPeer.PeerID != peer2ID {
		t.Error("192.168.1.100 should route to peer 2")
	}

	// No route for external IP
	_, found = p.LookupPeerByIP(net.ParseIP("8.8.8.8"))
	if found {
		t.Error("8.8.8.8 should not have a route")
	}
}

func TestGetPeers(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	// Initially empty
	peers := p.GetPeers()
	if len(peers) != 0 {
		t.Error("Should have no peers initially")
	}

	// Add a peer
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

	// Should have one peer
	peers = p.GetPeers()
	if len(peers) != 1 {
		t.Errorf("Should have 1 peer, got %d", len(peers))
	}
}

func TestInitiatePunchWithAllowedIPs(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	peerKeys, _ := GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	_, ipnet1, _ := net.ParseCIDR("10.0.0.0/8")
	_, ipnet2, _ := net.ParseCIDR("172.16.0.0/12")

	allowedIPs := []net.IPNet{*ipnet1, *ipnet2}

	// This will fail to send (no real peer), but should set up AllowedIPs
	peerAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65535}
	_ = p.InitiatePunchWithAllowedIPs(peerID, peerKeys.PublicKey, peerAddr, allowedIPs)

	// Verify AllowedIPs were registered
	gotAllowed := p.GetPeerAllowedIPs(peerID)
	if len(gotAllowed) != 2 {
		t.Fatalf("Expected 2 AllowedIPs, got %d", len(gotAllowed))
	}

	// Verify lookup works
	_, found := p.LookupPeerByIP(net.ParseIP("10.1.2.3"))
	if !found {
		t.Error("Should find peer for 10.1.2.3")
	}

	_, found = p.LookupPeerByIP(net.ParseIP("172.20.1.1"))
	if !found {
		t.Error("Should find peer for 172.20.1.1")
	}
}
