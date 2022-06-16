#!/usr/bin/env python3
import socket

PORT = 9999
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', PORT))
s.listen(1)

conn, addr = s.accept()
while True:
    request = conn.recv(1024)
    if not request:
         break

    reply = request.upper()
    conn.sendall(reply)

conn.close()
