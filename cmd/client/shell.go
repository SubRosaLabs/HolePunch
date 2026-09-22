package main

import (
	"fmt"
	"strings"
	"time"

	shellproto "github.com/abb3rrant/HolePunch/pkg/shell"
)

const shellResponseTimeout = 30 * time.Second

type shellPending struct {
	peerID   [32]byte
	response chan shellproto.Response
}

// handleShellPacket executes requests received over an authenticated peer
// channel. Responses are handled by the requesting operator, not re-executed.
func handleShellPacket(data []byte, send func([]byte) error) (bool, error) {
	if !shellproto.IsPacket(data) {
		return false, nil
	}
	request, err := shellproto.ParseRequest(data)
	if err != nil {
		if _, responseErr := shellproto.ParseResponse(data); responseErr == nil {
			return true, nil
		}
		return true, err
	}

	response := shellproto.Execute(request.Command)
	response.ID = request.ID
	wire, err := response.MarshalBinary()
	if err != nil {
		return true, err
	}
	return true, send(wire)
}

func (c *Client) handleShellResponse(peerID [32]byte, data []byte) bool {
	response, err := shellproto.ParseResponse(data)
	if err != nil {
		return false
	}
	c.shellMu.Lock()
	pending := c.shellResponses[response.ID]
	c.shellMu.Unlock()
	if pending == nil {
		return true
	}
	if pending.peerID != peerID {
		return false
	}
	select {
	case pending.response <- response:
	default:
	}
	return true
}

func (c *Client) cmdShell(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: shell <command>")
		return
	}

	c.stateMu.RLock()
	session := c.session
	c.stateMu.RUnlock()
	if session == nil || !session.Connected {
		fmt.Println("Select a connected agent first: session <id>")
		return
	}

	command := strings.Join(args, " ")
	c.shellMu.Lock()
	c.shellNextID++
	id := c.shellNextID
	responseCh := make(chan shellproto.Response, 1)
	c.shellResponses[id] = &shellPending{peerID: session.ID, response: responseCh}
	c.shellMu.Unlock()
	defer func() {
		c.shellMu.Lock()
		delete(c.shellResponses, id)
		c.shellMu.Unlock()
	}()

	request, err := (shellproto.Request{ID: id, Command: command}).MarshalBinary()
	if err != nil {
		fmt.Printf("shell: %v\n", err)
		return
	}
	if err := c.puncher.SendToPeer(session.ID, request); err != nil {
		fmt.Printf("shell send: %v\n", err)
		return
	}

	select {
	case response := <-responseCh:
		if len(response.Output) > 0 {
			fmt.Print(string(response.Output))
		}
		if response.ExitCode != 0 {
			fmt.Printf("[exit %d]\n", response.ExitCode)
		}
	case <-time.After(shellResponseTimeout):
		fmt.Println("shell: timed out waiting for agent response")
	}
}
