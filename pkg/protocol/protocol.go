// Package protocol defines the wire protocol for HolePunch communication
package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

// Message types
const (
	MsgTypeRegister     uint8 = 1  // Client registering with server
	MsgTypeRegisterAck  uint8 = 2  // Server acknowledging registration
	MsgTypePeerList     uint8 = 3  // Server sending list of peers
	MsgTypePunchRequest uint8 = 4  // Request to punch hole to peer
	MsgTypePunchInit    uint8 = 5  // Server telling client to initiate punch
	MsgTypePunchAck     uint8 = 6  // Acknowledgment of punch attempt
	MsgTypeData         uint8 = 7  // Encrypted data packet
	MsgTypeKeepalive    uint8 = 8  // Keepalive packet
	MsgTypeKeyExchange  uint8 = 9  // Key exchange for encryption
	MsgTypeDisconnect   uint8 = 10 // Client disconnecting
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
	header := Header{Version: 1, Type: MsgTypeRegister, Length: 64}
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

	header := Header{Version: 1, Type: MsgTypePunchInit, Length: uint16(64 + 2 + len(addrBytes))}
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
	header := Header{Version: 1, Type: MsgTypeData, Length: uint16(24 + len(m.Ciphertext))}
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
	header := Header{Version: 1, Type: MsgTypeKeyExchange, Length: 32}
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
