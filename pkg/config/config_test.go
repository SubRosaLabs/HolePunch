package config

import (
	"os"
	"testing"
	"time"
)

func TestVersionInfo(t *testing.T) {
	info := VersionInfo()
	if info == "" {
		t.Error("VersionInfo should not be empty")
	}
	if len(info) < 10 {
		t.Error("VersionInfo seems too short")
	}
}

func TestDefaultConfigs(t *testing.T) {
	client := DefaultClientConfig()
	if client == nil {
		t.Fatal("DefaultClientConfig returned nil")
	}
	if client.Keepalive != DefaultKeepalive {
		t.Error("Wrong default keepalive")
	}

	server := DefaultServerConfig()
	if server == nil {
		t.Fatal("DefaultServerConfig returned nil")
	}
	if server.MaxClients != DefaultMaxPeers {
		t.Error("Wrong default max clients")
	}
}

func TestStats(t *testing.T) {
	s := NewStats()
	if s == nil {
		t.Fatal("NewStats returned nil")
	}

	s.AddBytesSent(100)
	s.AddBytesReceived(200)
	s.AddPacketsSent(5)
	s.AddPacketsReceived(10)
	s.AddConnection()

	snap := s.Snapshot()
	if snap.BytesSent != 100 {
		t.Errorf("BytesSent: got %d, want 100", snap.BytesSent)
	}
	if snap.BytesReceived != 200 {
		t.Errorf("BytesReceived: got %d, want 200", snap.BytesReceived)
	}
	if snap.PacketsSent != 5 {
		t.Errorf("PacketsSent: got %d, want 5", snap.PacketsSent)
	}
	if snap.PacketsReceived != 10 {
		t.Errorf("PacketsReceived: got %d, want 10", snap.PacketsReceived)
	}
	if snap.Connections != 1 {
		t.Errorf("Connections: got %d, want 1", snap.Connections)
	}
}

func TestStatsActiveStreams(t *testing.T) {
	s := NewStats()

	s.IncrActiveStreams()
	s.IncrActiveStreams()
	s.IncrActiveStreams()

	snap := s.Snapshot()
	if snap.ActiveStreams != 3 {
		t.Errorf("ActiveStreams: got %d, want 3", snap.ActiveStreams)
	}

	s.DecrActiveStreams()
	snap = s.Snapshot()
	if snap.ActiveStreams != 2 {
		t.Errorf("ActiveStreams: got %d, want 2", snap.ActiveStreams)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input  uint64
		expect string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
	}

	for _, tc := range tests {
		got := FormatBytes(tc.input)
		if got != tc.expect {
			t.Errorf("FormatBytes(%d): got %s, want %s", tc.input, got, tc.expect)
		}
	}
}

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		input  time.Duration
		expect string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m30s"},
		{3600 * time.Second, "1h0m"},
		{25 * time.Hour, "1d1h"},
	}

	for _, tc := range tests {
		got := FormatDuration(tc.input)
		if got != tc.expect {
			t.Errorf("FormatDuration(%v): got %s, want %s", tc.input, got, tc.expect)
		}
	}
}

func TestConfigSaveLoad(t *testing.T) {
	tmpFile := "/tmp/holepunch_test_config.json"
	defer os.Remove(tmpFile)

	// Save config
	cfg := DefaultClientConfig()
	cfg.ServerAddr = "test.example.com:12345"

	err := SaveClientConfig(tmpFile, cfg)
	if err != nil {
		t.Fatalf("SaveClientConfig failed: %v", err)
	}

	// Load config
	loaded, err := LoadClientConfig(tmpFile)
	if err != nil {
		t.Fatalf("LoadClientConfig failed: %v", err)
	}

	if loaded.ServerAddr != cfg.ServerAddr {
		t.Errorf("ServerAddr: got %s, want %s", loaded.ServerAddr, cfg.ServerAddr)
	}
}

func TestLoadNonExistentConfig(t *testing.T) {
	cfg, err := LoadClientConfig("/nonexistent/path/config.json")
	if err != nil {
		t.Fatalf("Should return default config, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Should return default config")
	}
}

func TestUptime(t *testing.T) {
	s := NewStats()
	time.Sleep(10 * time.Millisecond)
	uptime := s.Uptime()
	if uptime < 10*time.Millisecond {
		t.Error("Uptime should be at least 10ms")
	}
}

func TestIdleTime(t *testing.T) {
	s := NewStats()
	time.Sleep(10 * time.Millisecond)
	idle := s.IdleTime()
	if idle < 10*time.Millisecond {
		t.Error("IdleTime should be at least 10ms")
	}

	// Activity should reset idle time
	s.AddBytesSent(1)
	idle = s.IdleTime()
	if idle > 5*time.Millisecond {
		t.Error("IdleTime should be near zero after activity")
	}
}

func TestStatsConcurrency(t *testing.T) {
	s := NewStats()
	done := make(chan bool)

	for i := 0; i < 100; i++ {
		go func() {
			s.AddBytesSent(1)
			s.AddBytesReceived(1)
			s.AddPacketsSent(1)
			s.AddPacketsReceived(1)
			s.IncrActiveStreams()
			s.DecrActiveStreams()
			_ = s.Snapshot()
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	snap := s.Snapshot()
	if snap.BytesSent != 100 {
		t.Errorf("BytesSent: got %d, want 100", snap.BytesSent)
	}
}
