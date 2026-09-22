// Package shell implements compact peer-to-peer request/response packets for
// authorized operator command execution.
package shell

import (
	"encoding/binary"
	"errors"
	"os/exec"
	"runtime"
)

const (
	packetMagic  = "HPSH"
	requestType  = 1
	responseType = 2

	// MaxCommandSize and MaxOutputSize keep shell packets below typical UDP path
	// MTUs after HolePunch encryption and framing.
	MaxCommandSize = 768
	MaxOutputSize  = 768
)

var errInvalidPacket = errors.New("invalid shell packet")

// Request asks a connected agent to execute Command.
type Request struct {
	ID      uint32
	Command string
}

// Response returns captured stdout/stderr and the process exit code.
type Response struct {
	ID       uint32
	ExitCode int32
	Output   []byte
}

// IsPacket reports whether data uses the shell packet prefix.
func IsPacket(data []byte) bool {
	return len(data) >= len(packetMagic) && string(data[:len(packetMagic)]) == packetMagic
}

// MarshalBinary serializes a command request.
func (r Request) MarshalBinary() ([]byte, error) {
	payload := []byte(r.Command)
	if len(payload) == 0 || len(payload) > MaxCommandSize {
		return nil, errors.New("command must be between 1 and 768 bytes")
	}
	return marshal(requestType, r.ID, 0, payload), nil
}

// MarshalBinary serializes a command response.
func (r Response) MarshalBinary() ([]byte, error) {
	if len(r.Output) > MaxOutputSize {
		r.Output = append([]byte(nil), r.Output[:MaxOutputSize]...)
	}
	return marshal(responseType, r.ID, r.ExitCode, r.Output), nil
}

func marshal(kind byte, id uint32, exitCode int32, payload []byte) []byte {
	buf := make([]byte, 17+len(payload))
	copy(buf, packetMagic)
	buf[4] = kind
	binary.BigEndian.PutUint32(buf[5:9], id)
	binary.BigEndian.PutUint32(buf[9:13], uint32(exitCode))
	binary.BigEndian.PutUint32(buf[13:17], uint32(len(payload)))
	copy(buf[17:], payload)
	return buf
}

func parse(data []byte, wantKind byte) (uint32, int32, []byte, error) {
	if len(data) < 17 || !IsPacket(data) || data[4] != wantKind {
		return 0, 0, nil, errInvalidPacket
	}
	length := int(binary.BigEndian.Uint32(data[13:17]))
	if length != len(data)-17 || length > MaxOutputSize {
		return 0, 0, nil, errInvalidPacket
	}
	payload := append([]byte(nil), data[17:]...)
	return binary.BigEndian.Uint32(data[5:9]), int32(binary.BigEndian.Uint32(data[9:13])), payload, nil
}

// ParseRequest parses a command request packet.
func ParseRequest(data []byte) (Request, error) {
	id, _, payload, err := parse(data, requestType)
	if err != nil || len(payload) == 0 || len(payload) > MaxCommandSize {
		return Request{}, errInvalidPacket
	}
	return Request{ID: id, Command: string(payload)}, nil
}

// ParseResponse parses a command response packet.
func ParseResponse(data []byte) (Response, error) {
	id, exitCode, output, err := parse(data, responseType)
	if err != nil {
		return Response{}, err
	}
	return Response{ID: id, ExitCode: exitCode, Output: output}, nil
}

// Execute runs one command through the platform shell and captures stdout and
// stderr. It intentionally has no privilege escalation behavior.
func Execute(command string) Response {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	output, err := cmd.CombinedOutput()
	result := Response{Output: output}
	if len(result.Output) > MaxOutputSize {
		result.Output = append(result.Output[:MaxOutputSize-len("\n[output truncated]\n")], "\n[output truncated]\n"...)
	}
	if err == nil {
		return result
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		returnCode := int32(exitErr.ExitCode())
		result.ExitCode = returnCode
		return result
	}
	result.ExitCode = 127
	if len(result.Output) == 0 {
		result.Output = []byte(err.Error())
	}
	return result
}
