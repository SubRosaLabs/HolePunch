"""
MyBox2: attacker-controlled receiver.
Listens on 445.  Traffic arriving here means the port-forward intercept worked.
"""
import socket, sys

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 445))
s.listen(5)
print("MyBox2: listening on 0.0.0.0:445  (waiting for intercepted traffic)", flush=True)

while True:
    conn, addr = s.accept()
    data = conn.recv(4096)
    print(f"MyBox2: ✓ INTERCEPTED connection from {addr}  data={data!r}", flush=True)
    conn.sendall(b"INTERCEPTED by MyBox2 - port forward is working\n")
    conn.close()
