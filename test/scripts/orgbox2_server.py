"""
OrgBox2: simulates the internal target.

 - Port 445: SMB intercept validator (existing test)
 - Port 8080: HTTP server for the EOF/web-forwarding test
   Serves an index page that references 4 assets so the test can verify
   that all parallel browser-style connections complete and close correctly.

If traffic arrives on 445, the intercept FAILED.
If all 4 HTTP assets load cleanly, the EOF fix is working.
"""
import socket, sys, threading, io, textwrap, time

# ── 445 intercept detector ────────────────────────────────────────────────

def run_445():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 445))
    s.listen(5)
    print("OrgBox2: listening on 0.0.0.0:445  (should NOT receive test traffic)", flush=True)
    while True:
        conn, addr = s.accept()
        data = conn.recv(4096)
        print(f"OrgBox2: !! UNEXPECTED CONNECTION from {addr} !!  data={data!r}", flush=True)
        conn.sendall(b"OrgBox2: traffic was NOT intercepted - something is wrong\n")
        conn.close()

# ── 8080 HTTP server for EOF/web test ────────────────────────────────────

ASSETS = {
    "/style.css":    b"body { color: red; }" + b"x" * 4096,
    "/script.js":    b"console.log('ok');" + b"x" * 8192,
    "/image.bin":    bytes(range(256)) * 200,   # ~50 KB binary
    "/data.txt":     b"data\n" * 2000,
}

INDEX_HTML = textwrap.dedent("""\
    <html><head>
      <link rel="stylesheet" href="/style.css">
      <script src="/script.js"></script>
    </head><body>
      <img src="/image.bin">
      <p>OrgBox2 HTTP test page — all assets should load</p>
    </body></html>
""").encode()

def http_response(status, body, content_type="application/octet-stream"):
    hdr  = f"HTTP/1.1 {status}\r\n"
    hdr += f"Content-Type: {content_type}\r\n"
    hdr += f"Content-Length: {len(body)}\r\n"
    hdr += "Connection: close\r\n\r\n"
    return hdr.encode() + body

def handle_http(conn, addr):
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk

        line = data.split(b"\r\n")[0].decode(errors="replace")
        parts = line.split()
        path = parts[1] if len(parts) >= 2 else "/"

        if path == "/" or path == "/index.html":
            resp = http_response("200 OK", INDEX_HTML, "text/html")
        elif path in ASSETS:
            resp = http_response("200 OK", ASSETS[path])
        else:
            resp = http_response("404 Not Found", b"not found")

        conn.sendall(resp)
        # Explicit graceful close — tests that the EOF is forwarded correctly.
        conn.shutdown(socket.SHUT_WR)
        time.sleep(0.01)
        conn.close()
        print(f"OrgBox2 HTTP: served {path} ({len(resp)} bytes) to {addr}", flush=True)
    except Exception as e:
        print(f"OrgBox2 HTTP: error serving {addr}: {e}", flush=True)
        conn.close()

def run_8080():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", 8080))
    s.listen(20)
    print("OrgBox2: HTTP server on 0.0.0.0:8080", flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_http, args=(conn, addr), daemon=True).start()

# ── main ──────────────────────────────────────────────────────────────────

threading.Thread(target=run_445, daemon=True).start()
run_8080()
