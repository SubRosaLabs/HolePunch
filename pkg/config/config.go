// Package config provides configuration and version information
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Build info - set via ldflags
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// VersionInfo returns formatted version string
func VersionInfo() string {
	return fmt.Sprintf("HolePunch %s (commit: %s, built: %s)", Version, Commit, BuildDate)
}

// Prompt is the interactive CLI prompt used by both the orchestrator
// and the client. It is only emitted when stdin is a TTY (see StdinIsTTY).
const Prompt = "[HolePunch] >> "

// StdinIsTTY reports whether os.Stdin is attached to a terminal. Used to
// gate the interactive prompt so piped/scripted invocations stay clean.
func StdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// Defaults
const (
	DefaultServerPort     = 443
	DefaultSOCKS5Port     = 1080
	DefaultKeepalive      = 25 * time.Second
	DefaultConnectTimeout = 10 * time.Second
	DefaultReadTimeout    = 60 * time.Second
	DefaultMaxPeers       = 100
	DefaultMaxStreams     = 1000
	DefaultMTU            = 1400
	DefaultTUNIP          = "240.0.0.1/24"
	DefaultTUNName        = "holepunch0"
)

// ClientConfig holds client configuration
type ClientConfig struct {
	ServerAddr     string        `json:"server_addr"`
	IPv6           bool          `json:"ipv6"`
	Keepalive      time.Duration `json:"keepalive"`
	ConnectTimeout time.Duration `json:"connect_timeout"`
	LogLevel       string        `json:"log_level"`
	TUNIP          string        `json:"tun_ip"`
	TUNName        string        `json:"tun_name"`
	MTU            int           `json:"mtu"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	ListenAddr    string        `json:"listen_addr"`
	IPv6          bool          `json:"ipv6"`
	MaxClients    int           `json:"max_clients"`
	ClientTimeout time.Duration `json:"client_timeout"`
	LogLevel      string        `json:"log_level"`
}

// DefaultClientConfig returns default client configuration
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		ServerAddr:     fmt.Sprintf("localhost:%d", DefaultServerPort),
		IPv6:           false,
		Keepalive:      DefaultKeepalive,
		ConnectTimeout: DefaultConnectTimeout,
		LogLevel:       "info",
		TUNIP:          DefaultTUNIP,
		TUNName:        DefaultTUNName,
		MTU:            DefaultMTU,
	}
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr:    fmt.Sprintf("0.0.0.0:%d", DefaultServerPort),
		IPv6:          false,
		MaxClients:    DefaultMaxPeers,
		ClientTimeout: 120 * time.Second,
		LogLevel:      "info",
	}
}

// LoadClientConfig loads client config from file
func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := DefaultClientConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// LoadServerConfig loads server config from file
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := DefaultServerConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// SaveClientConfig saves client config to file
func SaveClientConfig(path string, cfg *ClientConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// SaveServerConfig saves server config to file
func SaveServerConfig(path string, cfg *ServerConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
