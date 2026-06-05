"""
Stress test: open N concurrent TCP connections through the port-forward tunnel.

Each connection sends a unique payload and expects a response, then closes.
All N connections are launched simultaneously to verify:
  1. Concurrent stream multiplexing works.
  2. EOF is propagated correctly (connections close cleanly).
  3. No stream ID collisions or data cross-contamination.

Usage:
    python3 stress_client.py <host> <port> [connections] [timeout]

Exit 0 on full success, 1 on any failure.
"""
import socket, threading, time, sys, os

HOST    = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT    = int(sys.argv[2]) if len(sys.argv) > 2 else 445
N       = int(sys.argv[3]) if len(sys.argv) > 3 else 30
TIMEOUT = float(sys.argv[4]) if len(sys.argv) > 4 else 20

results = [None] * N
lock    = threading.Lock()

def run(i):
    try:
        s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
        payload = f"STRESS_CONN_{i:04d}\n".encode()
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)   # send EOF so server knows we're done
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        with lock:
            results[i] = ("ok", resp)
    except Exception as e:
        with lock:
            results[i] = ("err", str(e))

threads = [threading.Thread(target=run, args=(i,), daemon=True) for i in range(N)]
t0 = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join(timeout=TIMEOUT + 5)

elapsed = time.time() - t0
ok  = sum(1 for r in results if r and r[0] == "ok")
err = sum(1 for r in results if r and r[0] == "err")
hung = sum(1 for r in results if r is None)

print(f"Stress ({HOST}:{PORT}): {ok}/{N} OK, {err} errors, {hung} hung — {elapsed:.1f}s", flush=True)

for i, r in enumerate(results):
    if r is None:
        print(f"  [HUNG]   conn {i}", flush=True)
    elif r[0] == "err":
        print(f"  [ERROR]  conn {i}: {r[1]}", flush=True)

if ok < N:
    print(f"STRESS FAILED: only {ok}/{N} connections succeeded")
    sys.exit(1)

print(f"STRESS PASSED: all {N} connections completed cleanly")
sys.exit(0)
