//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

// createTun opens /dev/net/tun, configures the holepunch0 interface via
// ioctl TUNSETIFF, then assigns 240.0.0.1/24 and brings the link up via
// the `ip` command. Requires CAP_NET_ADMIN (typically sudo).
func (c *Client) createTun() error {
	c.tunnelIface = "holepunch0"

	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/net/tun: %v (run with sudo)", err)
	}

	// struct ifreq: 16-byte name, then 2-byte flags (IFF_TUN | IFF_NO_PI).
	var ifr [40]byte
	copy(ifr[:16], c.tunnelIface)
	ifr[16] = 0x01 // IFF_TUN
	ifr[17] = 0x10 // IFF_NO_PI

	const TUNSETIFF = 0x400454ca
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}

	c.tunFile = os.NewFile(uintptr(fd), "/dev/net/tun")

	cmd := exec.Command("ip", "addr", "add", "240.0.0.1/24", "dev", c.tunnelIface)
	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exists") {
			c.tunFile.Close()
			return fmt.Errorf("ip addr: %v: %s", err, out)
		}
	}

	exec.Command("ip", "link", "set", "dev", c.tunnelIface, "mtu", "1400").Run()

	cmd = exec.Command("ip", "link", "set", "dev", c.tunnelIface, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		c.tunFile.Close()
		return fmt.Errorf("ip link up: %v: %s", err, out)
	}

	return nil
}
