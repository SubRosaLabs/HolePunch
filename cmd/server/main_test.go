package main

import (
	"crypto/tls"
	"testing"
)

func TestPrewarmCertificateRequestsConfiguredDomain(t *testing.T) {
	const domain = "orchestrator.example.com"
	var gotHello *tls.ClientHelloInfo

	err := prewarmCertificate(domain, func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		gotHello = hello
		return &tls.Certificate{}, nil
	})
	if err != nil {
		t.Fatalf("prewarmCertificate() error = %v", err)
	}
	if gotHello.ServerName != domain {
		t.Errorf("certificate request ServerName = %q, want %q", gotHello.ServerName, domain)
	}
	if len(gotHello.SignatureSchemes) == 0 || len(gotHello.SupportedCurves) == 0 || len(gotHello.CipherSuites) == 0 {
		t.Fatal("prewarm ClientHello must advertise modern ECDSA capabilities")
	}
}
