package shell

import (
	"bytes"
	"testing"
)

func TestRequestRoundTrip(t *testing.T) {
	want := Request{ID: 42, Command: "printf hello"}

	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	if !IsPacket(wire) {
		t.Fatal("IsPacket() = false, want true")
	}

	got, err := ParseRequest(wire)
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if got.ID != want.ID || got.Command != want.Command {
		t.Errorf("ParseRequest() = %#v, want %#v", got, want)
	}
}

func TestResponseRoundTripPreservesExitStatusAndOutput(t *testing.T) {
	want := Response{ID: 7, ExitCode: 3, Output: []byte("permission denied\n")}

	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	got, err := ParseResponse(wire)
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if got.ID != want.ID || got.ExitCode != want.ExitCode || !bytes.Equal(got.Output, want.Output) {
		t.Errorf("ParseResponse() = %#v, want %#v", got, want)
	}
}

func TestExecuteCapturesStandardOutput(t *testing.T) {
	result := Execute("printf shell-ok")
	if result.ExitCode != 0 {
		t.Fatalf("Execute() exit code = %d, output = %q", result.ExitCode, result.Output)
	}
	if got := string(result.Output); got != "shell-ok" {
		t.Errorf("Execute() output = %q, want %q", got, "shell-ok")
	}
}
