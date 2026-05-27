//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

// createTun is a stub on non-Linux platforms. TUN mode requires Linux's
// /dev/net/tun + TUNSETIFF ioctl — use SOCKS5 or port forwarding instead.
func (c *Client) createTun() error {
	return fmt.Errorf("TUN mode requires Linux (current OS: %s). Use SOCKS5: 'socks start' then proxychains nmap -sT <target>", runtime.GOOS)
}
