"""
Local receiver on mybox1 for the reverse listener test.

Listens on 127.0.0.1:4445.  When the rlistener is set up on orgbox1:4445,
inbound connections from external parties are forwarded here.

Prints a clear REVERSE_INTERCEPTED line so run_test.sh can grep for it.
"""
import socket, threading, sys

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 4445))
s.listen(10)
print("MyBox1 rlistener receiver: 127.0.0.1:4445 (waiting for reverse-forwarded traffic)", flush=True)

def handle(conn, addr):
    data = conn.recv(4096)
    print(f"MyBox1 rlistener: ✓ REVERSE_INTERCEPTED from {addr}  data={data!r}", flush=True)
    conn.sendall(b"REVERSE_INTERCEPTED by MyBox1 rlistener\n")
    conn.close()

while True:
    conn, addr = s.accept()
    threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
