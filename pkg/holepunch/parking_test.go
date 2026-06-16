package holepunch

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// addPeerFull inserts a peer into all puncher internal maps without doing any
// network I/O. Tests that exercise HandlePacket need addrToPeer populated.
func addPeerFull(p *Puncher, localKeys *KeyPair, peerKeys *KeyPair, addr *net.UDPAddr) ([32]byte, *PeerConnection) {
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	secret, _ := ComputeSharedSecret(&localKeys.PrivateKey, &peerKeys.PublicKey)
	enc, _ := NewEncryptor(secret)

	peer := &PeerConnection{
		PeerID:    peerID,
		PublicKey: peerKeys.PublicKey,
		Addr:      addr,
		Encryptor: enc,
		LastSeen:  time.Now(),
	}

	p.peersMu.Lock()
	p.peers[peerID] = peer
	p.pubKeyToPeer[peerKeys.PublicKey] = peerID
	p.addrToPeer[addr.String()] = peerID
	p.peersMu.Unlock()

	return peerID, peer
}

// keepalivePkt builds a valid keepalive wire packet.
func keepalivePkt() []byte {
	h := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeKeepalive, Length: 0}
	return h.Serialize()
}

// ---------- PeerCount ----------

func TestPeerCount_Empty(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	if n := p.PeerCount(); n != 0 {
		t.Errorf("got %d, want 0", n)
	}
}

func TestPeerCount_WithPeers(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	for i := 0; i < 3; i++ {
		pk, _ := GenerateKeyPair()
		addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20000 + i})
	}

	if n := p.PeerCount(); n != 3 {
		t.Errorf("got %d, want 3", n)
	}
}

// ---------- touchPeer ----------

func TestTouchPeer_FiresConnCallbackExactlyOnce(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20100})

	var count int32
	p.SetPeerConnectedHandler(func(_ [32]byte) { atomic.AddInt32(&count, 1) })

	p.touchPeer(peer)
	p.touchPeer(peer)
	p.touchPeer(peer)

	time.Sleep(30 * time.Millisecond)

	if got := atomic.LoadInt32(&count); got != 1 {
		t.Errorf("onPeerConn fired %d times, want 1", got)
	}
}

func TestTouchPeer_SetsConfirmed(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20101})

	if peer.confirmed {
		t.Fatal("peer should not be confirmed before touchPeer")
	}

	p.touchPeer(peer)

	peer.mu.RLock()
	confirmed := peer.confirmed
	peer.mu.RUnlock()

	if !confirmed {
		t.Error("peer should be confirmed after touchPeer")
	}
}

func TestTouchPeer_UpdatesLastSeen(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20102})

	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Minute)
	peer.mu.Unlock()

	before := time.Now()
	p.touchPeer(peer)
	after := time.Now()

	peer.mu.RLock()
	seen := peer.LastSeen
	peer.mu.RUnlock()

	if seen.Before(before) || seen.After(after) {
		t.Errorf("LastSeen %v not in [%v, %v]", seen, before, after)
	}
}

func TestTouchPeer_NoCallbackWhenHandlerNil(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20103})

	// No handler set — must not panic.
	p.touchPeer(peer)
	time.Sleep(10 * time.Millisecond)
}

// ---------- ReapStalePeers ----------

func TestReapStalePeers_RemovesStale(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20200})

	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Hour)
	peer.mu.Unlock()

	p.ReapStalePeers(time.Second)

	if n := p.PeerCount(); n != 0 {
		t.Errorf("stale peer not removed; count=%d", n)
	}
}

func TestReapStalePeers_KeepsFreshPeer(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20201})

	p.ReapStalePeers(time.Minute)

	if n := p.PeerCount(); n != 1 {
		t.Errorf("fresh peer was reaped; count=%d", n)
	}
}

func TestReapStalePeers_FiresDiscCallback(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	peerID, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20202})

	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Hour)
	peer.mu.Unlock()

	fired := make(chan [32]byte, 1)
	p.SetPeerDisconnectedHandler(func(id [32]byte) { fired <- id })

	p.ReapStalePeers(time.Second)

	select {
	case id := <-fired:
		if id != peerID {
			t.Errorf("callback got wrong ID: %x want %x", id, peerID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("onPeerDisc not fired")
	}
}

func TestReapStalePeers_NoCallbackForFreshPeer(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20203})

	var called bool
	p.SetPeerDisconnectedHandler(func(_ [32]byte) { called = true })

	p.ReapStalePeers(time.Minute)
	time.Sleep(20 * time.Millisecond)

	if called {
		t.Error("onPeerDisc fired for a fresh peer")
	}
}

func TestReapStalePeers_CleansAllMaps(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	addr := &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20204}
	peerID, peer := addPeerFull(p, keys, pk, addr)

	_, ipnet, _ := net.ParseCIDR("10.99.0.0/24")
	_ = p.AddAllowedIP(peerID, *ipnet)

	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Hour)
	peer.mu.Unlock()

	p.ReapStalePeers(time.Second)

	p.peersMu.RLock()
	defer p.peersMu.RUnlock()

	if _, ok := p.peers[peerID]; ok {
		t.Error("peers map not cleaned")
	}
	if _, ok := p.pubKeyToPeer[pk.PublicKey]; ok {
		t.Error("pubKeyToPeer not cleaned")
	}
	if _, ok := p.addrToPeer[addr.String()]; ok {
		t.Error("addrToPeer not cleaned")
	}
	if _, ok := p.ipToPeer[ipnet.String()]; ok {
		t.Error("ipToPeer not cleaned")
	}
}

func TestReapStalePeers_PartialReap(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	stalePK, _ := GenerateKeyPair()
	_, stalePeer := addPeerFull(p, keys, stalePK, &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 20205})
	stalePeer.mu.Lock()
	stalePeer.LastSeen = time.Now().Add(-time.Hour)
	stalePeer.mu.Unlock()

	freshPK, _ := GenerateKeyPair()
	freshID, _ := addPeerFull(p, keys, freshPK, &net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 20206})

	reaped := make(chan [32]byte, 2)
	p.SetPeerDisconnectedHandler(func(id [32]byte) { reaped <- id })

	p.ReapStalePeers(time.Second)

	if n := p.PeerCount(); n != 1 {
		t.Errorf("want 1 peer, got %d", n)
	}

	peers := p.GetPeers()
	if len(peers) != 1 || peers[0] != freshID {
		t.Errorf("wrong survivor: %v", peers)
	}

	select {
	case <-reaped:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("disc callback not fired for stale peer")
	}
}

func TestReapStalePeers_MultipleStale_AllCallbacksFired(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	const N = 4
	for i := 0; i < N; i++ {
		pk, _ := GenerateKeyPair()
		_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("3.3.3.3"), Port: 20300 + i})
		peer.mu.Lock()
		peer.LastSeen = time.Now().Add(-time.Hour)
		peer.mu.Unlock()
	}

	var count int32
	p.SetPeerDisconnectedHandler(func(_ [32]byte) { atomic.AddInt32(&count, 1) })

	p.ReapStalePeers(time.Second)

	// Disc callbacks are synchronous in ReapStalePeers.
	if got := atomic.LoadInt32(&count); got != N {
		t.Errorf("got %d disc callbacks, want %d", got, N)
	}
	if n := p.PeerCount(); n != 0 {
		t.Errorf("peers remain after full reap: %d", n)
	}
}

func TestReapStalePeers_UnconfirmedPeerIsReaped(t *testing.T) {
	// A peer that never sent data (confirmed=false) should still be reaped once
	// its LastSeen (set at creation) expires.
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	_, peer := addPeerFull(p, keys, pk, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 20400})

	peer.mu.Lock()
	peer.confirmed = false
	peer.LastSeen = time.Now().Add(-time.Hour)
	peer.mu.Unlock()

	var discFired bool
	p.SetPeerDisconnectedHandler(func(_ [32]byte) { discFired = true })

	p.ReapStalePeers(time.Second)

	if p.PeerCount() != 0 {
		t.Error("unconfirmed stale peer not reaped")
	}
	if !discFired {
		t.Error("onPeerDisc should fire for unconfirmed reaped peer")
	}
}

// ---------- HandlePacket / keepalive path ----------

func TestHandleKeepalive_FiresConnCallbackOnce(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("5.5.5.5"), Port: 20500}
	addPeerFull(p, keys, pk, peerAddr)

	connected := make(chan struct{}, 5)
	p.SetPeerConnectedHandler(func(_ [32]byte) { connected <- struct{}{} })

	pkt := keepalivePkt()
	for i := 0; i < 3; i++ {
		if err := p.HandlePacket(pkt, peerAddr); err != nil {
			t.Fatalf("HandlePacket: %v", err)
		}
	}

	time.Sleep(40 * time.Millisecond)

	if got := len(connected); got != 1 {
		t.Errorf("onPeerConn fired %d times, want 1", got)
	}
}

func TestHandleKeepalive_UpdatesLastSeen(t *testing.T) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("5.5.5.5"), Port: 20501}
	_, peer := addPeerFull(p, keys, pk, peerAddr)

	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Minute)
	peer.mu.Unlock()

	before := time.Now()
	_ = p.HandlePacket(keepalivePkt(), peerAddr)
	after := time.Now()

	peer.mu.RLock()
	seen := peer.LastSeen
	peer.mu.RUnlock()

	if seen.Before(before) || seen.After(after) {
		t.Errorf("LastSeen %v not in [%v, %v]", seen, before, after)
	}
}

func TestHandleKeepalive_UnknownAddr_NoCallback(t *testing.T) {
	// Keepalive from an address not in addrToPeer must be silently dropped.
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	var called bool
	p.SetPeerConnectedHandler(func(_ [32]byte) { called = true })

	unknown := &net.UDPAddr{IP: net.ParseIP("9.9.9.9"), Port: 9999}
	_ = p.HandlePacket(keepalivePkt(), unknown)

	time.Sleep(20 * time.Millisecond)
	if called {
		t.Error("callback fired for unknown address")
	}
}

// ---------- Full lifecycle: connected → reaped ----------

func TestPeerConnDisc_Lifecycle(t *testing.T) {
	// Peer added → keepalive fires "connected" callback → LastSeen pushed old →
	// reap fires "disconnected" callback. This exercises the complete park/unpark
	// trigger path at the Puncher layer.
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("7.7.7.7"), Port: 20600}
	_, peer := addPeerFull(p, keys, pk, peerAddr)

	events := make(chan string, 4)
	p.SetPeerConnectedHandler(func(_ [32]byte) { events <- "connected" })
	p.SetPeerDisconnectedHandler(func(_ [32]byte) { events <- "disconnected" })

	_ = p.HandlePacket(keepalivePkt(), peerAddr)

	select {
	case ev := <-events:
		if ev != "connected" {
			t.Fatalf("first event: got %q, want connected", ev)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("connected callback not fired")
	}

	if p.PeerCount() != 1 {
		t.Fatalf("peer count: got %d, want 1", p.PeerCount())
	}

	// Age out the peer and reap.
	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Hour)
	peer.mu.Unlock()

	p.ReapStalePeers(time.Second)

	select {
	case ev := <-events:
		if ev != "disconnected" {
			t.Fatalf("second event: got %q, want disconnected", ev)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("disconnected callback not fired")
	}

	if p.PeerCount() != 0 {
		t.Errorf("peer count after reap: %d, want 0", p.PeerCount())
	}
}

func TestPeerConnDisc_ReconnectFiresCallbackAgain(t *testing.T) {
	// After a peer is reaped and re-added, the connected callback fires again
	// on first contact — confirming the parking cycle can repeat.
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	defer conn.Close()

	keys, _ := GenerateKeyPair()
	p := NewPuncher(conn, keys)

	pk, _ := GenerateKeyPair()
	peerAddr := &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 20700}

	var count int32
	p.SetPeerConnectedHandler(func(_ [32]byte) { atomic.AddInt32(&count, 1) })

	// First connection.
	_, peer := addPeerFull(p, keys, pk, peerAddr)
	_ = p.HandlePacket(keepalivePkt(), peerAddr)
	time.Sleep(30 * time.Millisecond)

	// Reap.
	peer.mu.Lock()
	peer.LastSeen = time.Now().Add(-time.Hour)
	peer.mu.Unlock()
	p.ReapStalePeers(time.Second)

	// Second connection.
	_, _ = addPeerFull(p, keys, pk, peerAddr)
	_ = p.HandlePacket(keepalivePkt(), peerAddr)
	time.Sleep(30 * time.Millisecond)

	if got := atomic.LoadInt32(&count); got != 2 {
		t.Errorf("expected 2 connect callbacks across two connections, got %d", got)
	}
}
