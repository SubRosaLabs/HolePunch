<p align="center">
  <img src="assets/holepunch.png" alt="HolePunch" width="220">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go Version">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge" alt="Platform">
</p>

<p align="center">UDP hole-punching VPN for network pivoting. Drop a rootless agent behind any NAT, punch through from your operator box via a public orchestrator, tunnel in.</p>

---

## Build

```bash
make build           # -> bin/holepunch-server, bin/holepunch-client
make release         # cross-compile linux/macos/windows
make test            # go test -race ./...
```

Requires Go 1.24+. Pre-built binaries: [Releases](https://github.com/abb3rrant/HolePunch/releases).

## Quick start

Three roles, two binaries:

| Role | Binary | Needs |
|---|---|---|
| Orchestrator | `holepunch-server` | Public IP, UDP/41234 open inbound |
| Agent | `holepunch-client` | Outbound UDP only, no root |
| Operator | `holepunch-client` | Sudo only for TUN mode |

**1. Orchestrator (public VPS)**

```bash
./holepunch-server
# 2026/04/23 22:30:00 HolePunch v1.0.0
# 2026/04/23 22:30:00 Listening on 0.0.0.0:41234 (max clients: 100)
[HolePunch] >>
```

**2. Agent (target machine)**

```bash
./holepunch-client -server vps.example.com:41234
# Client ID: 8964d3cdd927e4c5
# Registered with server
```

Passive — leave it running.

**3. Operator (your box)**

```bash
sudo ./holepunch-client -server vps.example.com:41234   # sudo only for TUN
# Agent discovered: 8964d3cd at 162.243.95.178:55279
[HolePunch] >> session 8964
Session: 8964d3cd
```

Now pick a mode.

## Modes

### SOCKS5 (any OS, rootless)

TCP-only proxy. Works everywhere.

```
[HolePunch] >> socks start
SOCKS5 started: 127.0.0.1:1080
```

```bash
curl --socks5 127.0.0.1:1080 http://192.168.1.1
proxychains nmap -sT -Pn 192.168.1.0/24      # /etc/proxychains.conf -> socks5 127.0.0.1 1080
ssh -o ProxyCommand='nc -x 127.0.0.1:1080 %h %p' user@192.168.1.10
```

### Port forward (any OS, rootless)

Expose specific remote services locally.

```
[HolePunch] >> listener add 2222:192.168.1.10:22
Listener: 127.0.0.1:2222 -> 192.168.1.10:22
```

```bash
ssh -p 2222 user@localhost
```

### TUN (Linux operator, sudo)

Full L3 — run tools natively, no proxychains.

```
[HolePunch] >> tunnel start
Tunnel holepunch0 is up
[HolePunch] >> route add 192.168.1.0/24
Route added: 192.168.1.0/24 (AllowedIP for peer)
```

```bash
nmap -sT -Pn 192.168.1.0/24
ssh user@192.168.1.10
curl http://192.168.1.1
```

Target sees the agent's IP as source. Use `-sT` (connect scan); `-sS` needs raw sockets on your side and bypasses TUN.

### Cleanup

```
[HolePunch] >> tunnel stop
[HolePunch] >> socks stop
[HolePunch] >> listener del 2222
[HolePunch] >> quit
```

## Commands

### Operator / agent

```
agents                          List discovered agents
session <id>                    Select agent (prefix match)

tunnel start | stop             TUN interface (Linux + sudo)
route add | del <cidr>          AllowedIP cryptokey routes
route list                      Show routes
ifconfig                        Show interface + peer state

socks start [port]              SOCKS5 proxy (default 1080)
socks stop

listener add <lp>:<host>:<rp>   Local port forward
listener del <port>
listener list

stats | version | help | quit
```

### Orchestrator

```
clients         List registered clients with endpoints and last-seen
stats           Traffic counters + uptime
version | help | quit
```

## Flags

```
holepunch-server [-bind 0.0.0.0] [-port 41234] [-max-clients 100] [-6] [-version]
holepunch-client [-server localhost:41234] [-6] [-version]
```

## Limitations

- **TUN is Linux only.** macOS TUN is a stub — use SOCKS5/port forward there.
- **Symmetric NATs** may block the punch. If `session <id>` hangs, that's usually why.
- **`nmap -sS`** uses raw sockets on the operator and bypasses the tunnel — use `-sT`.
- **SOCKS5 UDP ASSOCIATE** is not implemented (TCP only).
- **IPv4 only** on the data plane (orchestrator coordination supports `-6`).
- **No orchestrator auth** — run on a non-obvious port or behind a firewall allowlist.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center"><sub>Built for red-team pivoting. Use only on networks you're authorized to test.</sub></p>
