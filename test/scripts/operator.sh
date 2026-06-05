#!/bin/bash
# Automates the operator CLI using a FIFO so we avoid needing 'expect'.
# Runs inside the mybox1 container.
set -euo pipefail

ORCHESTRATOR="${ORCHESTRATOR:-orchestrator:41234}"
MYBOX2="${MYBOX2:-mybox2}"

# The bind-mount from a Windows/NTFS path arrives as 0777; holepunch-client
# refuses keys that aren't 0600.  Copy to a tmpfs path first.
cp /keys/operator.key /tmp/operator.key
chmod 0600 /tmp/operator.key
KEY="/tmp/operator.key"
LOG="/tmp/hp.log"
PIPE="/tmp/hp_cmd"

mkfifo "$PIPE"

echo "[mybox1] starting operator client..."
# Start client with stdin from the FIFO; both stdout and stderr go to the log
# file.  Because stdin is not a TTY, the interactive shell skips the prompt,
# making the log clean to grep.
holepunch-client -server "$ORCHESTRATOR" -key "$KEY" -ignorecert < "$PIPE" >"$LOG" 2>&1 &
HP_PID=$!

# Hold the write end open so the FIFO never EOF's the client.
exec 4>"$PIPE"

send_cmd() { echo "$1" >&4; }

wait_log() {
    local pattern="$1" label="$2" timeout="${3:-30}"
    for i in $(seq 1 "$timeout"); do
        grep -q "$pattern" "$LOG" 2>/dev/null && { echo "[mybox1] $label"; return 0; }
        sleep 1
    done
    echo "[mybox1] TIMEOUT waiting for: $label"
    echo "[mybox1] --- log tail ---"
    tail -20 "$LOG"
    return 1
}

# ── Step 1: operator auth ────────────────────────────────────────────────────
wait_log "Operator authentication granted" "operator authenticated"

# ── Step 2: wait for peer list (server sends it right after auth) ────────────
wait_log "Agent discovered:" "agent discovered" 20

AGENT_ID=$(sed -n 's/.*Agent discovered: \([0-9a-f]*\) at.*/\1/p' "$LOG" | head -1)
echo "[mybox1] agent ID: $AGENT_ID"

# ── Step 3: open session (triggers hole punch) ───────────────────────────────
send_cmd "session $AGENT_ID"
wait_log "Session:" "session established" 15

# ── Step 4: set up SMB port forward (existing Test 1 & 2) ────────────────────
# OrgBox1 dials mybox2:445 for every local connection on 127.0.0.1:445
send_cmd "listener add 445:${MYBOX2}:445"
wait_log "Listener:" "SMB listener ready" 10

echo ""
echo "[mybox1] ✓ Port forward ready"
echo "[mybox1]   local  : 127.0.0.1:445 (on MyBox1)"
echo "[mybox1]   via    : OrgBox1 (agent)"
echo "[mybox1]   dials  : ${MYBOX2}:445"
echo ""

# ── Step 5: set up HTTP forward for EOF/web test (Test 3) ────────────────────
# OrgBox1 dials 172.30.0.10:8080 (OrgBox2 HTTP server on orgnet)
send_cmd "listener add 8080:172.30.0.10:8080"
wait_log "Port forward: localhost:8080" "HTTP listener ready" 10

echo "[mybox1] ✓ HTTP listener ready: 127.0.0.1:8080 -> OrgBox2:8080"

# ── Step 6: reverse listener (Test 4) ────────────────────────────────────────
# Start local receiver on 127.0.0.1:4445 in background.
python3 /scripts/mybox1_rlistener_server.py >/tmp/rlistener.log 2>&1 &
sleep 1   # give it a moment to bind

# Tell OrgBox1 to bind 0.0.0.0:4445; inbound connections flow back to here.
send_cmd "rlistener add 4445:127.0.0.1:4445"
wait_log "Reverse listener: agent:0.0.0.0:4445" "rlistener ready" 15

echo "[mybox1] ✓ Reverse listener ready: OrgBox1:4445 -> 127.0.0.1:4445"

# Stay alive so listeners remain active for the tests.
wait "$HP_PID"
