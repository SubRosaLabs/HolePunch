// Package protocol defines the wire protocol for HolePunch communication
package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

// Wire-format version. Bumped to 2 when operator authentication was added:
// RegisterAck now carries a session nonce body, and AuthRequest / AuthResult
// messages were introduced. A v1 client cannot interoperate with a v2 server
// (and vice versa) — Header.Version mismatches are dropped at handlePacket.
const WireVersion uint8 = 2

// Message types
const (
	MsgTypeRegister     uint8 = 1  // Client registering with server
	MsgTypeRegisterAck  uint8 = 2  // Server acknowledging registration (+ session nonce)
	MsgTypePeerList     uint8 = 3  // Server sending list of peers (operators only)
	MsgTypePunchRequest uint8 = 4  // Request to punch hole to peer (operators only)
	MsgTypePunchInit    uint8 = 5  // Server telling client to initiate punch
	MsgTypePunchAck     uint8 = 6  // Acknowledgment of punch attempt
	MsgTypeData         uint8 = 7  // Encrypted data packet
	MsgTypeKeepalive    uint8 = 8  // Keepalive packet
	MsgTypeKeyExchange  uint8 = 9  // Key exchange for encryption
	MsgTypeDisconnect   uint8 = 10 // Client disconnecting
	MsgTypeAuthRequest  uint8 = 11 // Operator presenting Ed25519 pubkey + signature
	MsgTypeAuthResult   uint8 = 12 // Server granting or denying operator role
)

// Header is the common header for all messages
type Header struct {
	Version uint8
	Type    uint8
	Length  uint16
}

const HeaderSize = 4

// ParseHeader parses a header from bytes
func ParseHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("data too short for header")
	}
	return &Header{
		Version: data[0],
		Type:    data[1],
		Length:  binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

// Serialize serializes the header to bytes
func (h *Header) Serialize() []byte {
	buf := make([]byte, HeaderSize)
	buf[0] = h.Version
	buf[1] = h.Type
	binary.BigEndian.PutUint16(buf[2:4], h.Length)
	return buf
}

// RegisterMessage is sent by client to register with the server
type RegisterMessage struct {
	ClientID  [32]byte // Unique client identifier
	PublicKey [32]byte // X25519 public key for encryption
}

// Serialize serializes the register message
func (m *RegisterMessage) Serialize() []byte {
	header := Header{Version: WireVersion, Type: MsgTypeRegister, Length: 64}
	buf := header.Serialize()
	buf = append(buf, m.ClientID[:]...)
	buf = append(buf, m.PublicKey[:]...)
	return buf
}

// ParseRegisterMessage parses a register message from bytes
func ParseRegisterMessage(data []byte) (*RegisterMessage, error) {
	if len(data) < 64 {
		return nil, errors.New("data too short for register message")
	}
	msg := &RegisterMessage{}
	copy(msg.ClientID[:], data[0:32])
	copy(msg.PublicKey[:], data[32:64])
	return msg, nil
}

// RegisterAckMessage acknowledges registration and provides a per-connection
// SessionNonce that operator clients must sign with their Ed25519 private key
// to prove identity in a follow-up AuthRequestMessage.
type RegisterAckMessage struct {
	SessionNonce [32]byte
}

// Serialize serializes the register ack.
func (m *RegisterAckMessage) Serialize() []byte {
	header := Header{Version: WireVersion, Type: MsgTypeRegisterAck, Length: 32}
	buf := header.Serialize()
	buf = append(buf, m.SessionNonce[:]...)
	return buf
}

// ParseRegisterAckMessage parses a register ack from bytes.
func ParseRegisterAckMessage(data []byte) (*RegisterAckMessage, error) {
	if len(data) < 32 {
		return nil, errors.New("data too short for register ack")
	}
	msg := &RegisterAckMessage{}
	copy(msg.SessionNonce[:], data[0:32])
	return msg, nil
}

// AuthRequestMessage is sent by an operator client after RegisterAck to prove
// possession of an Ed25519 private key whose public key appears in the
// orchestrator's authorized_keys file. The signature covers
// (sigPrefix || SessionNonce || ClientID); see pkg/auth.
type AuthRequestMessage struct {
	PublicKey [32]byte // Ed25519
	Signature [64]byte
}

// Serialize serializes the auth request.
func (m *AuthRequestMessage) Serialize() []byte {
	header := Header{Version: WireVersion, Type: MsgTypeAuthRequest, Length: 96}
	buf := header.Serialize()
	buf = append(buf, m.PublicKey[:]...)
	buf = append(buf, m.Signature[:]...)
	return buf
}

// ParseAuthRequestMessage parses an auth request from bytes.
func ParseAuthRequestMessage(data []byte) (*AuthRequestMessage, error) {
	if len(data) < 96 {
		return nil, errors.New("data too short for auth request")
	}
	msg := &AuthRequestMessage{}
	copy(msg.PublicKey[:], data[0:32])
	copy(msg.Signature[:], data[32:96])
	return msg, nil
}

// AuthResultMessage tells a client whether the orchestrator granted operator
// role. On denial the client silently continues as an agent.
type AuthResultMessage struct {
	Granted bool
}

// Serialize serializes the auth result.
func (m *AuthResultMessage) Serialize() []byte {
	header := Header{Version: WireVersion, Type: MsgTypeAuthResult, Length: 1}
	buf := header.Serialize()
	if m.Granted {
		buf = append(buf, 1)
	} else {
		buf = append(buf, 0)
	}
	return buf
}

// ParseAuthResultMessage parses an auth result from bytes.
func ParseAuthResultMessage(data []byte) (*AuthResultMessage, error) {
	if len(data) < 1 {
		return nil, errors.New("data too short for auth result")
	}
	return &AuthResultMessage{Granted: data[0] != 0}, nil
}

// PeerInfo contains information about a peer
type PeerInfo struct {
	ClientID  [32]byte
	PublicKey [32]byte
	Addr      *net.UDPAddr
}

// PunchInitMessage tells a client to initiate a hole punch
type PunchInitMessage struct {
	PeerID        [32]byte
	PeerPublicKey [32]byte
	PeerAddr      *net.UDPAddr
}

// Serialize serializes the punch init message
func (m *PunchInitMessage) Serialize() []byte {
	addrBytes := m.PeerAddr.IP.To4()
	if addrBytes == nil {
		addrBytes = m.PeerAddr.IP.To16()
	}

	header := Header{Version: WireVersion, Type: MsgTypePunchInit, Length: uint16(64 + 2 + len(addrBytes))}
	buf := header.Serialize()
	buf = append(buf, m.PeerID[:]...)
	buf = append(buf, m.PeerPublicKey[:]...)

	// Port (2 bytes) + IP length (1 byte) + IP bytes
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(m.PeerAddr.Port))
	buf = append(buf, portBytes...)
	buf = append(buf, byte(len(addrBytes)))
	buf = append(buf, addrBytes...)

	return buf
}

// ParsePunchInitMessage parses a punch init message.
// The IP bytes are copied (not aliased into the caller's data buffer) so the
// returned message stays valid after data is reused, e.g. when data is a
// reused receive buffer.
func ParsePunchInitMessage(data []byte) (*PunchInitMessage, error) {
	if len(data) < 67 { // 64 + 2 + 1 minimum
		return nil, errors.New("data too short for punch init message")
	}

	msg := &PunchInitMessage{}
	copy(msg.PeerID[:], data[0:32])
	copy(msg.PeerPublicKey[:], data[32:64])

	port := binary.BigEndian.Uint16(data[64:66])
	ipLen := int(data[66])

	if len(data) < 67+ipLen {
		return nil, errors.New("data too short for IP address")
	}

	ip := make(net.IP, ipLen)
	copy(ip, data[67:67+ipLen])
	msg.PeerAddr = &net.UDPAddr{IP: ip, Port: int(port)}

	return msg, nil
}

// DataMessage wraps encrypted data
type DataMessage struct {
	Nonce      [24]byte
	Ciphertext []byte
}

// Serialize serializes the data message
func (m *DataMessage) Serialize() []byte {
	header := Header{Version: WireVersion, Type: MsgTypeData, Length: uint16(24 + len(m.Ciphertext))}
	buf := header.Serialize()
	buf = append(buf, m.Nonce[:]...)
	buf = append(buf, m.Ciphertext...)
	return buf
}

// ParseDataMessage parses a data message
func ParseDataMessage(data []byte) (*DataMessage, error) {
	if len(data) < 24 {
		return nil, errors.New("data too short for data message")
	}
	msg := &DataMessage{}
	copy(msg.Nonce[:], data[0:24])
	msg.Ciphertext = data[24:]
	return msg, nil
}

// KeyExchangeMessage for establishing encrypted channel
type KeyExchangeMessage struct {
	PublicKey [32]byte
}

// Serialize serializes the key exchange message
func (m *KeyExchangeMessage) Serialize() []byte {
	header := Header{Version: WireVersion, Type: MsgTypeKeyExchange, Length: 32}
	buf := header.Serialize()
	buf = append(buf, m.PublicKey[:]...)
	return buf
}

// ParseKeyExchangeMessage parses a key exchange message
func ParseKeyExchangeMessage(data []byte) (*KeyExchangeMessage, error) {
	if len(data) < 32 {
		return nil, errors.New("data too short for key exchange message")
	}
	msg := &KeyExchangeMessage{}
	copy(msg.PublicKey[:], data[0:32])
	return msg, nil
}
