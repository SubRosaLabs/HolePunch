package main

import (
	"net"
	"testing"
	"time"

	"github.com/abb3rrant/HolePunch/pkg/holepunch"
	"github.com/abb3rrant/HolePunch/pkg/protocol"
)

// newTestClient creates a minimal Client backed by a real UDP socket (port 0).
// The caller must close c.conn when done.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient("127.0.0.1:1", "/agent", false, nil, true)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { c.conn.Close() })
	return c
}

// addTestPeer inserts a peer directly into the puncher's internal maps without
// network I/O, mirroring the helper used in the holepunch package tests.
func addTestPeer(t *testing.T, p *holepunch.Puncher, localKeys *holepunch.KeyPair, addr *net.UDPAddr) [32]byte {
	t.Helper()
	peerKeys, err := holepunch.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// Use InitiatePunchWithAllowedIPs which sets up all maps without actually
	// sending — it will fail to write (no server) but the maps are populated
	// before any I/O. We ignore the error.
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])
	_ = p.InitiatePunchWithAllowedIPs(peerID, peerKeys.PublicKey, addr, nil)
	return peerID
}

// ---------- isParked ----------

func TestIsParked_InitiallyFalse(t *testing.T) {
	c := newTestClient(t)
	if c.isParked() {
		t.Error("new client should not be parked")
	}
}

// ---------- parkServerChannel ----------

func TestParkServerChannel_SetsParkedFlag(t *testing.T) {
	c := newTestClient(t)
	c.parkServerChannel()
	if !c.isParked() {
		t.Error("isParked should be true after parkServerChannel")
	}
}

func TestParkServerChannel_NoOpForOperator(t *testing.T) {
	c := newTestClient(t)
	c.stateMu.Lock()
	c.isOperator = true
	c.stateMu.Unlock()

	c.parkServerChannel()

	if c.isParked() {
		t.Error("operator should never be parked")
	}
}

func TestParkServerChannel_Idempotent(t *testing.T) {
	c := newTestClient(t)
	c.parkServerChannel()
	c.parkServerChannel() // second call must be a no-op; must not panic or double-close
	if !c.isParked() {
		t.Error("should still be parked after double park")
	}
}

func TestParkServerChannel_NilFieldsSafe(t *testing.T) {
	// serverPipe / serverResp / serverRT are nil when never connected.
	// closeServerChannel must not panic.
	c := newTestClient(t)
	c.parkServerChannel() // internally calls closeServerChannel on nil fields
}

// ---------- unparkServerChannel ----------

func TestUnparkServerChannel_NoOpIfNotParked(t *testing.T) {
	c := newTestClient(t)
	// not parked → should return without doing anything (and without panicking)
	c.unparkServerChannel()
	if c.isParked() {
		t.Error("should not be parked after no-op unpark")
	}
}

func TestUnparkServerChannel_ClearsParkedFlag(t *testing.T) {
	c := newTestClient(t)
	c.parkServerChannel()

	// Cancel the context so connect() fails fast (QUIC dial aborts immediately).
	c.cancelCtx()

	c.unparkServerChannel()

	// Give the reconnect goroutine time to attempt and fail.
	time.Sleep(50 * time.Millisecond)

	if c.isParked() {
		t.Error("isParked should be false after unparkServerChannel")
	}
}

func TestUnparkServerChannel_NoOpWhileShuttingDown(t *testing.T) {
	c := newTestClient(t)
	c.parkServerChannel()

	// Simulate shutdown without triggering the full Shutdown() cascade.
	close(c.shutdown)
	c.unparkServerChannel()

	// parked was set to false by the time unparkServerChannel hit the shutdown
	// select, so the flag should be false.
	if c.isParked() {
		t.Error("should not be parked after unpark during shutdown")
	}
}

// ---------- reconnectServerChannel ----------

func TestReconnectServerChannel_NoOpIfAlreadyReconnecting(t *testing.T) {
	c := newTestClient(t)
	c.cancelCtx() // make connect() fail fast

	c.stateMu.Lock()
	c.reconnecting = true
	c.stateMu.Unlock()

	// Should return immediately because reconnecting flag is set.
	done := make(chan struct{})
	go func() {
		c.reconnectServerChannel()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Error("reconnectServerChannel did not exit immediately when already reconnecting")
	}
}

func TestReconnectServerChannel_ExitsOnShutdown(t *testing.T) {
	c := newTestClient(t)
	// Cancel ctx AND close shutdown so connect() fails AND the retry select
	// exits immediately.
	c.cancelCtx()
	close(c.shutdown)

	done := make(chan struct{})
	go func() {
		c.reconnectServerChannel()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("reconnectServerChannel did not exit on shutdown")
	}
}

func TestReconnectServerChannel_ExitsWhenParked(t *testing.T) {
	c := newTestClient(t)
	c.cancelCtx() // ensure connect() fails fast after the immediate attempt

	// Park BEFORE calling reconnect; the isParked() check fires immediately.
	c.stateMu.Lock()
	c.parked = true
	c.stateMu.Unlock()

	done := make(chan struct{})
	go func() {
		c.reconnectServerChannel()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Error("reconnectServerChannel did not exit when client is parked")
	}
}

func TestReconnectServerChannel_ClearsReconnectingFlagOnExit(t *testing.T) {
	c := newTestClient(t)
	c.cancelCtx()
	close(c.shutdown)

	c.reconnectServerChannel()

	c.stateMu.RLock()
	reconnecting := c.reconnecting
	c.stateMu.RUnlock()

	if reconnecting {
		t.Error("reconnecting flag should be cleared after reconnectServerChannel returns")
	}
}

func TestServerConnectionDrop_TriggersReconnectNotShutdown(t *testing.T) {
	// Simulate what serverReceiveLoop does when the server drops the connection:
	// it should spawn reconnectServerChannel, NOT call Shutdown().
	// We verify by checking the client is NOT shut down after the event.
	c := newTestClient(t)
	c.cancelCtx() // makes reconnect attempts fail immediately (context cancelled)

	// The reconnect goroutine will try connect(), fail fast, wait 5s, ...
	// We don't wait for reconnect; we just check the client is still alive.
	go c.reconnectServerChannel()

	time.Sleep(30 * time.Millisecond)

	select {
	case <-c.shutdown:
		t.Error("client shutdown — reconnect should keep client alive")
	default:
		// expected: client still running
	}
}

// ---------- closeServerChannel ----------

func TestCloseServerChannel_SafeOnNilFields(t *testing.T) {
	c := newTestClient(t)
	// Must not panic when all server channel fields are nil.
	c.closeServerChannel()
	c.closeServerChannel() // idempotent
}

// ---------- onPeerConnected ----------

func TestOnPeerConnected_AgentParks(t *testing.T) {
	c := newTestClient(t)
	// Default: isOperator = false → agent.

	var peerID [32]byte
	c.onPeerConnected(peerID)

	if !c.isParked() {
		t.Error("agent should park when a peer connects")
	}
}

func TestOnPeerConnected_OperatorDoesNotPark(t *testing.T) {
	c := newTestClient(t)
	c.stateMu.Lock()
	c.isOperator = true
	c.stateMu.Unlock()

	var peerID [32]byte
	c.onPeerConnected(peerID)

	if c.isParked() {
		t.Error("operator must not park on peer connect")
	}
}

func TestOnPeerConnected_MarksPeerConnected(t *testing.T) {
	c := newTestClient(t)

	var peerID [32]byte
	hexID := "0000000000000000" // first 8 bytes of zero ID as hex
	c.peersMu.Lock()
	c.peers[hexID] = &PeerEntry{ID: peerID}
	c.peersMu.Unlock()

	c.onPeerConnected(peerID)

	c.peersMu.RLock()
	connected := c.peers[hexID].Connected
	c.peersMu.RUnlock()

	if !connected {
		t.Error("peer Connected flag should be set to true on onPeerConnected")
	}
}

// ---------- onPeerDisconnected ----------

func TestOnPeerDisconnected_UnparksWhenLastPeerGone(t *testing.T) {
	c := newTestClient(t)
	c.cancelCtx() // prevent connect() from blocking when unpark triggers reconnect

	// Park the agent first.
	c.parkServerChannel()

	// Puncher has 0 peers → PeerCount() == 0 → should unpark.
	var peerID [32]byte
	c.onPeerDisconnected(peerID)

	if c.isParked() {
		t.Error("agent should unpark when last peer disconnects")
	}
}

func TestOnPeerDisconnected_StaysParkedWithRemainingPeers(t *testing.T) {
	c := newTestClient(t)

	// Add a peer to the puncher (PeerCount > 0 after this peer disconnects).
	_ = addTestPeer(t, c.puncher, c.keys, &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 55000})

	c.parkServerChannel()

	// Fire disconnected for a *different* peer ID — puncher still has 1 peer.
	var otherID [32]byte
	otherID[0] = 0xFF
	c.onPeerDisconnected(otherID)

	if !c.isParked() {
		t.Error("should stay parked while other peers are still active")
	}
}

func TestOnPeerDisconnected_OperatorNeverUnparks(t *testing.T) {
	c := newTestClient(t)
	c.stateMu.Lock()
	c.isOperator = true
	c.stateMu.Unlock()

	// Even if parked (shouldn't happen in normal flow, but guard against it),
	// an operator must not try to unpark.
	c.stateMu.Lock()
	c.parked = true
	c.stateMu.Unlock()

	var peerID [32]byte
	// Should not panic and should not attempt connect().
	c.onPeerDisconnected(peerID)

	// Parked flag is unchanged because operator branch exits early.
	if !c.isParked() {
		t.Error("operator parked state should not be changed by onPeerDisconnected")
	}
}

func TestOnPeerDisconnected_ClearsPeerEntry(t *testing.T) {
	c := newTestClient(t)
	c.cancelCtx()

	var peerID [32]byte
	hexID := "0000000000000000"
	c.peersMu.Lock()
	c.peers[hexID] = &PeerEntry{ID: peerID}
	c.peersMu.Unlock()

	c.onPeerDisconnected(peerID)

	c.peersMu.RLock()
	_, exists := c.peers[hexID]
	c.peersMu.RUnlock()

	if exists {
		t.Error("peer entry should be deleted on disconnect")
	}
}

func TestOnPeerDisconnected_ClearsSession(t *testing.T) {
	c := newTestClient(t)
	c.cancelCtx()

	var peerID [32]byte

	c.stateMu.Lock()
	c.session = &PeerEntry{ID: peerID}
	c.stateMu.Unlock()

	c.onPeerDisconnected(peerID)

	c.stateMu.RLock()
	session := c.session
	c.stateMu.RUnlock()

	if session != nil {
		t.Error("session should be cleared when its peer disconnects")
	}
}

// ---------- keepalive + parking interaction ----------

func TestKeepalivedPeer_TriggersParkViaHandler(t *testing.T) {
	// Full puncher→client signal path: a keepalive packet from a registered peer
	// causes the puncher to fire onPeerConnected, which parks the agent.
	c := newTestClient(t)

	peerKeys, _ := holepunch.GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	peerAddr := &net.UDPAddr{IP: net.ParseIP("6.6.6.6"), Port: 55100}

	// Manually insert the peer into the puncher maps (same technique as
	// addPeerFull in the holepunch package tests, but via exported API paths
	// since we're in package main).
	_ = c.puncher.InitiatePunchWithAllowedIPs(peerID, peerKeys.PublicKey, peerAddr, nil)

	// Fire a keepalive — puncher marks peer confirmed and calls onPeerConnected.
	h := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeKeepalive, Length: 0}
	pkt := h.Serialize()
	_ = c.puncher.HandlePacket(pkt, peerAddr)

	// The onPeerConnected callback is invoked in a goroutine by the puncher.
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if c.isParked() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !c.isParked() {
		t.Error("agent should be parked after keepalive confirms the holepunch")
	}
}

func TestReapedPeer_TriggersUnparkViaHandler(t *testing.T) {
	// After the agent is parked (holepunch live) and then the peer is reaped,
	// onPeerDisconnected fires and the agent unparks.
	c := newTestClient(t)
	c.cancelCtx() // prevent connect() from blocking on reconnect attempt

	peerKeys, _ := holepunch.GenerateKeyPair()
	var peerID [32]byte
	copy(peerID[:], peerKeys.PublicKey[:])

	peerAddr := &net.UDPAddr{IP: net.ParseIP("6.6.6.6"), Port: 55200}
	_ = c.puncher.InitiatePunchWithAllowedIPs(peerID, peerKeys.PublicKey, peerAddr, nil)

	// Confirm the peer via keepalive → parks the agent.
	h2 := protocol.Header{Version: protocol.WireVersion, Type: protocol.MsgTypeKeepalive, Length: 0}
	_ = c.puncher.HandlePacket(h2.Serialize(), peerAddr)

	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if c.isParked() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !c.isParked() {
		t.Fatal("precondition: agent should be parked")
	}

	// Reap the peer (simulates 3 missed keepalives expiring).
	// We reach into the puncher and age the peer out via direct reap call.
	c.puncher.ReapStalePeers(0) // timeout=0 reaps everything immediately

	// onPeerDisconnected runs synchronously (ReapStalePeers calls the callback
	// directly), so unpark should be complete by the time ReapStalePeers returns.
	if c.isParked() {
		t.Error("agent should be unparked after peer is reaped")
	}
}
