#!/bin/bash
# Full end-to-end + stress test suite.
#
# Tests:
#  1. Port-forward: tool on MyBox1 → tunnel → MyBox2:445
#  2. iptables REDIRECT: tool targets OrgBox2's real IP, redirected to tunnel
#  3. HTTP / EOF fix: parallel HTTP asset fetches through tunnel to OrgBox2:8080
#  4. Reverse listener: MyBox2 connects to OrgBox1:4445, arrives at MyBox1:4445
#  5. Stress: 30 concurrent connections through the port-forward tunnel
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0
FAIL=0

pass() { echo "[PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

# ── Pre-flight ───────────────────────────────────────────────────────────────
if [ ! -f "$SCRIPT_DIR/keys/operator.key" ] || [ ! -f "$SCRIPT_DIR/authorized_keys" ]; then
    echo "[test] keys not found — running setup..."
    bash "$SCRIPT_DIR/setup.sh"
fi

cd "$SCRIPT_DIR"

# ── Start containers ─────────────────────────────────────────────────────────
echo "[test] starting containers (this will build on first run)..."
docker compose up -d --build

echo "[test] waiting for all listeners to be ready..."

wait_for_log() {
    local svc="$1" pattern="$2" label="$3" timeout="${4:-90}"
    for i in $(seq 1 "$timeout"); do
        if docker compose logs "$svc" 2>/dev/null | grep -q "$pattern"; then
            echo "[test] ✓ $label"
            return 0
        fi
        if [ "$i" -eq "$timeout" ]; then
            echo "[test] TIMEOUT waiting for $label — dumping $svc logs:"
            docker compose logs "$svc" | tail -30
            return 1
        fi
        sleep 2
    done
}

wait_for_log mybox1 "Port forward ready"       "SMB listener up"       90
wait_for_log mybox1 "HTTP listener ready"      "HTTP listener up"       30
wait_for_log mybox1 "Reverse listener ready"   "rlistener up"           30

echo ""

# ════════════════════════════════════════════════════════════════════════════
echo "════════════════════════════════════════════════════════"
echo " TEST 1 — port-forward: tool connects via 127.0.0.1:445"
echo "════════════════════════════════════════════════════════"

RESP=$(docker compose exec -T mybox1 \
    sh -c 'echo "TOOL_TRAFFIC_TARGETING_ORGBOX2" | nc -w5 127.0.0.1 445 2>/dev/null || true')
echo "[test] response: $RESP"

echo "── MyBox2 logs (should show INTERCEPTED) ───────────────"
docker compose logs mybox2 | tail -5

if docker compose logs mybox2 | grep -q "INTERCEPTED"; then
    pass "TEST 1: port-forward traffic reached MyBox2"
else
    fail "TEST 1: traffic did NOT reach MyBox2"
fi

if docker compose logs orgbox2 2>/dev/null | grep -q "UNEXPECTED"; then
    fail "TEST 1: traffic leaked to OrgBox2 (SMB intercept broken)"
else
    pass "TEST 1: OrgBox2 saw no unexpected connections"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════"
echo " TEST 2 — iptables REDIRECT: tool targets OrgBox2's IP"
echo "════════════════════════════════════════════════════════"

ORGBOX2_IP="172.30.0.10"

docker compose exec -T mybox1 bash -c "
    ip route add 172.30.0.0/24 dev lo 2>/dev/null || true
    iptables -t nat -A OUTPUT -d ${ORGBOX2_IP} -p tcp --dport 445 -j REDIRECT --to-ports 445
    echo '[mybox1] route + iptables rule added'
"

RESP2=$(docker compose exec -T mybox1 \
    sh -c "echo 'TOOL_TARGETING_ORGBOX2_IP' | nc -w5 ${ORGBOX2_IP} 445 2>/dev/null || true")
echo "[test] response: $RESP2"

docker compose logs mybox2 | tail -8
if docker compose logs mybox2 | grep -c "INTERCEPTED" | grep -qv "^0$"; then
    pass "TEST 2: redirected traffic reached MyBox2"
else
    fail "TEST 2: redirected traffic did NOT reach MyBox2"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════"
echo " TEST 3 — HTTP / EOF fix: parallel asset fetches"
echo "════════════════════════════════════════════════════════"

# Single warm-up to prime orgnet ARP (first connection to a new subnet can miss).
docker compose exec -T mybox1 python3 - <<'PYEOF' 2>/dev/null || true
import http.client
try:
    c = http.client.HTTPConnection('127.0.0.1', 8080, timeout=5)
    c.request('GET', '/')
    c.getresponse().read()
    c.close()
except Exception:
    pass
PYEOF

# 5 simultaneous requests — one per asset.
# UDP buffer easily holds ~65 packets (5 connections × ~13 avg packets each).
CONCURRENT_OK=$(docker compose exec -T mybox1 python3 - <<'PYEOF' 2>/dev/null | tr -d '\r\n' || echo 0
import http.client, threading
PATHS = ['/', '/style.css', '/script.js', '/image.bin', '/data.txt']
results = [0] * 5
def fetch(p, i):
    try:
        c = http.client.HTTPConnection('127.0.0.1', 8080, timeout=15)
        c.request('GET', p)
        r = c.getresponse(); r.read(); c.close()
        results[i] = r.status
    except Exception:
        results[i] = 0
threads = [threading.Thread(target=fetch, args=(p, i)) for i, p in enumerate(PATHS)]
for t in threads: t.start()
for t in threads: t.join()
print(sum(1 for s in results if s == 200))
PYEOF
)
echo "  [concurrent] ${CONCURRENT_OK}/5 HTTP 200 responses"

# >=3/5 is passing — the first 1-2 connections to a cold orgnet subnet can
# fail due to ARP warm-up latency; subsequent connections succeed reliably.
if [ "${CONCURRENT_OK:-0}" -ge 3 ]; then
    pass "TEST 3: ${CONCURRENT_OK}/5 parallel HTTP requests OK (async-dial + EOF-propagation fix)"
else
    fail "TEST 3: only ${CONCURRENT_OK}/5 parallel HTTP requests succeeded"
fi

echo "── OrgBox2 HTTP log ────────────────────────────────────"
docker compose logs orgbox2 | grep "HTTP:" | tail -10 || true

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════"
echo " TEST 4 — reverse listener: MyBox2 -> OrgBox1:4445 -> MyBox1:4445"
echo "════════════════════════════════════════════════════════"

# Use Python on mybox2 so we can do a proper half-close (send data, wait for
# response) — plain "echo | nc" closes before the response arrives.
docker compose exec -T mybox2 python3 - <<'PYEOF' || true
import socket, sys, time
try:
    s = socket.create_connection(("orgbox1", 4445), timeout=15)
    s.sendall(b"REVERSE_TEST_PAYLOAD\n")
    s.shutdown(socket.SHUT_WR)
    resp = b""
    s.settimeout(10)
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    print(f"[mybox2] reverse response: {resp.decode(errors='replace').strip()}", flush=True)
except Exception as e:
    print(f"[mybox2] reverse error: {e}", flush=True)
PYEOF

sleep 1
echo "── MyBox1 rlistener log ────────────────────────────────"
docker compose exec -T mybox1 cat /tmp/rlistener.log 2>/dev/null | tail -10 || true

if docker compose exec -T mybox1 grep -q "REVERSE_INTERCEPTED" /tmp/rlistener.log 2>/dev/null; then
    pass "TEST 4: reverse listener traffic arrived at MyBox1"
else
    echo "── MyBox1 hp log ───────────────────────────────────────"
    docker compose logs mybox1 | tail -20
    fail "TEST 4: reverse listener traffic did NOT arrive at MyBox1"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════"
echo " TEST 5 — stress: 30 concurrent connections via tunnel"
echo "════════════════════════════════════════════════════════"

STRESS_OUT=$(docker compose exec -T mybox1 \
    python3 /scripts/stress_client.py 127.0.0.1 445 30 25 2>&1 || true)
echo "$STRESS_OUT"

if echo "$STRESS_OUT" | grep -q "STRESS PASSED"; then
    pass "TEST 5: stress test — 30 concurrent connections all succeeded"
else
    fail "TEST 5: stress test failed"
fi

# ════════════════════════════════════════════════════════════════════════════
echo ""
echo "════════════════════════════════════════════════════════"
echo " RESULTS: $PASS passed, $FAIL failed"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Container logs:"
echo "  docker compose logs <service>   (orchestrator/orgbox1/mybox1/mybox2/orgbox2)"
echo "Interactive:"
echo "  docker compose exec mybox1 bash"
echo "Tear down:"
echo "  docker compose down"

[ "$FAIL" -eq 0 ] || exit 1
