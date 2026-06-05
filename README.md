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

Three roles, two binaries. Operator role is gated by an Ed25519 keypair —
without a key the client runs as a passive agent, period.

| Role | Binary | Needs |
|---|---|---|
| Orchestrator | `holepunch-server` | Public IP, UDP/41234 open inbound, `authorized_keys` file |
| Agent | `holepunch-client` | Outbound UDP only, no root, **no key** |
| Operator | `holepunch-client` | Ed25519 private key + sudo (TUN only) |

**0. One-time operator setup**

On your operator box, generate a keypair:

```bash
./holepunch-client -keygen ~/.holepunch/operator.key
# Generated Ed25519 operator keypair:
#   private: ~/.holepunch/operator.key (0600)
#   public:  ~/.holepunch/operator.key.pub (0644)
#
# Add this line to the orchestrator's authorized_keys file:
#   z9Rk8...44chars==  # operator@kali
```

Copy the printed line into `authorized_keys` on the orchestrator (one base64
pubkey per line; `#` for comments).

**1. Orchestrator (public VPS)**

```bash
./holepunch-server
# 2026/04/23 22:30:00 HolePunch v1.0.0
# 2026/04/23 22:30:00 Listening on 0.0.0.0:41234 (max clients: 100)
# 2026/04/23 22:30:00 Loaded 1 operator key(s) from ./authorized_keys
[HolePunch] >>
```

`-authorized-keys <path>` overrides the default `./authorized_keys`. If the
file is missing or empty the server logs a loud warning and runs with zero
operators allowed (so every connected client stays an agent).

**2. Agent (target machine)**

```bash
./holepunch-client -server vps.example.com:41234
# Client ID: 8964d3cdd927e4c5
# Registered with server
```

Passive — leave it running. No key means no operator commands in the shell
and no peer-list visibility; a captured binary can't enumerate the fleet or
request punches.

**3. Operator (your box)**

```bash
sudo ./holepunch-client -server vps.example.com:41234 -key ~/.holepunch/operator.key
# Client ID: 8964d3cdd927e4c5
# Registered with server
# Operator authentication granted
# Agent discovered: 8964d3cd at 162.243.95.178:55279
[HolePunch] >> session 8964
Session: 8964d3cd
```

If `Operator authentication denied` shows instead, the orchestrator either
isn't running with your pubkey in its `authorized_keys` or the file's empty —
the agent shell still works but the operator commands are gated off.

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

### Reverse listener (any OS, rootless)

Expose a service running **on your operator box** through the agent. The agent
binds a public port; inbound connections are tunneled back and land on a local
address you specify. Useful for Responder, SMB relay, custom listeners, etc.

```
[HolePunch] >> rlistener add 445:127.0.0.1:445
Requesting agent to bind 0.0.0.0:445...
Reverse listener: agent:0.0.0.0:445 -> 127.0.0.1:445
```

Traffic flow:
```
External Box ──TCP──► Agent:445 ──tunnel──► Operator:127.0.0.1:445 ──► Your tool
```

Manage:
```
[HolePunch] >> rlistener list
Reverse Listeners:
  agent:0.0.0.0:445 -> 127.0.0.1:445

[HolePunch] >> rlistener del 445
Reverse listener removed: 445
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

listener add <lp>:<host>:<rp>   Local port forward via agent
listener del <port>
listener list

rlistener add <bp>:<host>:<rp>  Agent binds port, forwards inbound to operator
rlistener del <port>
rlistener list

stats | version | help | quit
```

### Orchestrator

```
clients         List registered clients with endpoints, role, and last-seen
operators       List authorized operators and current connection status
stats           Traffic counters + uptime
version | help | quit
```

## Flags

```
holepunch-server [-bind 0.0.0.0] [-port 41234] [-max-clients 100] [-6]
                 [-authorized-keys ./authorized_keys] [-version]

holepunch-client [-server localhost:41234] [-6] [-version]
                 [-key <path>]                # run as operator with this Ed25519 private key
                 [-keygen <path>]             # one-shot: generate operator keypair and exit
```

## Limitations

- **TUN is Linux only.** macOS TUN is a stub — use SOCKS5/port forward there.
- **Symmetric NATs** may block the punch. If `session <id>` hangs, that's usually why.
- **`nmap -sS`** uses raw sockets on the operator and bypasses the tunnel — use `-sT`.
- **SOCKS5 UDP ASSOCIATE** is not implemented (TCP only).
- **IPv4 only** on the data plane (orchestrator coordination supports `-6`).
- **Agents are unauthenticated.** Anyone who runs the binary can register as an
  agent and show up in operators' peer lists. Operator auth only gates the
  ability to *use* the fleet, not to *join* it. Add a per-agent allowlist on
  the orchestrator if you need stronger fleet-membership control.
- **No orchestrator-identity pinning on clients.** Clients trust whatever
  orchestrator address they were pointed at. If the orchestrator is MITM'd at
  the network level, the operator's auth signature is still bound to the
  attacker's session nonce — but the punch coordination itself can be tampered.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center"><sub>Built for red-team pivoting. Use only on networks you're authorized to test.</sub></p>
