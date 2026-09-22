package main

import (
	"os"
	"path/filepath"
	"testing"

	shellproto "github.com/abb3rrant/HolePunch/pkg/shell"
)

func TestHandleShellPacketExecutesRequestAndReturnsResponse(t *testing.T) {
	request, err := (shellproto.Request{ID: 9, Command: "printf agent-ok"}).MarshalBinary()
	if err != nil {
		t.Fatalf("request marshal: %v", err)
	}

	var sent []byte
	handled, err := handleShellPacket(request, func(data []byte) error {
		sent = append([]byte(nil), data...)
		return nil
	})
	if err != nil {
		t.Fatalf("handleShellPacket() error = %v", err)
	}
	if !handled {
		t.Fatal("handleShellPacket() handled = false, want true")
	}

	response, err := shellproto.ParseResponse(sent)
	if err != nil {
		t.Fatalf("response parse: %v", err)
	}
	if response.ID != 9 || response.ExitCode != 0 || string(response.Output) != "agent-ok" {
		t.Errorf("response = %#v, want successful output for request 9", response)
	}
}

func TestOperatorDoesNotExecuteShellRequestsFromAgent(t *testing.T) {
	c := newTestClient(t)
	c.stateMu.Lock()
	c.isOperator = true
	c.stateMu.Unlock()

	marker := filepath.Join(t.TempDir(), "operator-compromised")
	request, err := (shellproto.Request{ID: 10, Command: "touch " + marker}).MarshalBinary()
	if err != nil {
		t.Fatalf("request marshal: %v", err)
	}

	c.onDataReceived([32]byte{1}, request)

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("operator executed an agent-supplied command; stat error = %v", err)
	}
}

func TestShellResponseMustComeFromRequestedPeer(t *testing.T) {
	c := newTestClient(t)
	wantPeer := [32]byte{1}
	wrongPeer := [32]byte{2}
	responses := make(chan shellproto.Response, 1)
	c.shellResponses[11] = &shellPending{peerID: wantPeer, response: responses}

	wire, err := (shellproto.Response{ID: 11, Output: []byte("ok")}).MarshalBinary()
	if err != nil {
		t.Fatalf("response marshal: %v", err)
	}
	if c.handleShellResponse(wrongPeer, wire) {
		t.Fatal("accepted shell response from the wrong peer")
	}
	select {
	case <-responses:
		t.Fatal("delivered shell response from the wrong peer")
	default:
	}
	if !c.handleShellResponse(wantPeer, wire) {
		t.Fatal("rejected shell response from the requested peer")
	}
	select {
	case got := <-responses:
		if string(got.Output) != "ok" {
			t.Fatalf("response output = %q, want ok", got.Output)
		}
	default:
		t.Fatal("did not deliver response from the requested peer")
	}
}
