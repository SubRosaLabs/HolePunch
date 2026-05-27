package config

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Stats tracks connection statistics
type Stats struct {
	// Connection stats
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64

	// Error stats
	EncryptErrors  uint64
	DecryptErrors  uint64
	ReplayBlocked  uint64
	DroppedPackets uint64

	// Connection stats
	Connections   uint64
	ActiveStreams int64
	Reconnects    uint64

	// Timing
	StartTime    time.Time
	LastActivity time.Time

	mu sync.RWMutex
}

// NewStats creates a new stats tracker
func NewStats() *Stats {
	return &Stats{
		StartTime:    time.Now(),
		LastActivity: time.Now(),
	}
}

// AddBytesSent adds to bytes sent counter
func (s *Stats) AddBytesSent(n uint64) {
	atomic.AddUint64(&s.BytesSent, n)
	s.touch()
}

// AddBytesReceived adds to bytes received counter
func (s *Stats) AddBytesReceived(n uint64) {
	atomic.AddUint64(&s.BytesReceived, n)
	s.touch()
}

// AddPacketsSent increments packets sent
func (s *Stats) AddPacketsSent(n uint64) {
	atomic.AddUint64(&s.PacketsSent, n)
}

// AddPacketsReceived increments packets received
func (s *Stats) AddPacketsReceived(n uint64) {
	atomic.AddUint64(&s.PacketsReceived, n)
}

// AddEncryptError increments encrypt error counter
func (s *Stats) AddEncryptError() {
	atomic.AddUint64(&s.EncryptErrors, 1)
}

// AddDecryptError increments decrypt error counter
func (s *Stats) AddDecryptError() {
	atomic.AddUint64(&s.DecryptErrors, 1)
}

// AddReplayBlocked increments replay blocked counter
func (s *Stats) AddReplayBlocked() {
	atomic.AddUint64(&s.ReplayBlocked, 1)
}

// AddDroppedPacket increments dropped packet counter
func (s *Stats) AddDroppedPacket() {
	atomic.AddUint64(&s.DroppedPackets, 1)
}

// AddConnection increments connection counter
func (s *Stats) AddConnection() {
	atomic.AddUint64(&s.Connections, 1)
}

// AddReconnect increments reconnect counter
func (s *Stats) AddReconnect() {
	atomic.AddUint64(&s.Reconnects, 1)
}

// SetActiveStreams sets the active stream count
func (s *Stats) SetActiveStreams(n int64) {
	atomic.StoreInt64(&s.ActiveStreams, n)
}

// IncrActiveStreams increments active streams
func (s *Stats) IncrActiveStreams() {
	atomic.AddInt64(&s.ActiveStreams, 1)
}

// DecrActiveStreams decrements active streams
func (s *Stats) DecrActiveStreams() {
	atomic.AddInt64(&s.ActiveStreams, -1)
}

func (s *Stats) touch() {
	s.mu.Lock()
	s.LastActivity = time.Now()
	s.mu.Unlock()
}

// Uptime returns how long the connection has been up
func (s *Stats) Uptime() time.Duration {
	return time.Since(s.StartTime)
}

// IdleTime returns how long since last activity
func (s *Stats) IdleTime() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastActivity)
}

// Snapshot returns a copy of current stats
func (s *Stats) Snapshot() StatsSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return StatsSnapshot{
		BytesSent:       atomic.LoadUint64(&s.BytesSent),
		BytesReceived:   atomic.LoadUint64(&s.BytesReceived),
		PacketsSent:     atomic.LoadUint64(&s.PacketsSent),
		PacketsReceived: atomic.LoadUint64(&s.PacketsReceived),
		EncryptErrors:   atomic.LoadUint64(&s.EncryptErrors),
		DecryptErrors:   atomic.LoadUint64(&s.DecryptErrors),
		ReplayBlocked:   atomic.LoadUint64(&s.ReplayBlocked),
		DroppedPackets:  atomic.LoadUint64(&s.DroppedPackets),
		Connections:     atomic.LoadUint64(&s.Connections),
		ActiveStreams:   atomic.LoadInt64(&s.ActiveStreams),
		Reconnects:      atomic.LoadUint64(&s.Reconnects),
		Uptime:          s.Uptime(),
		IdleTime:        time.Since(s.LastActivity),
	}
}

// StatsSnapshot is a point-in-time copy of stats
type StatsSnapshot struct {
	BytesSent       uint64
	BytesReceived   uint64
	PacketsSent     uint64
	PacketsReceived uint64
	EncryptErrors   uint64
	DecryptErrors   uint64
	ReplayBlocked   uint64
	DroppedPackets  uint64
	Connections     uint64
	ActiveStreams   int64
	Reconnects      uint64
	Uptime          time.Duration
	IdleTime        time.Duration
}

// FormatBytes formats bytes as human-readable string
func FormatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats duration as human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	return fmt.Sprintf("%dd%dh", days, hours)
}
