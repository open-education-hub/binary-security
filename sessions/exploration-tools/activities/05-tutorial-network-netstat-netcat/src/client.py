#!/usr/bin/env python3
import socket

PORT = 9999
MESSAGE = "anaaremere"
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', PORT))

request = MESSAGE
print(f"sending '{request}'")
s.sendall(request.encode("utf-8"))
response = s.recv(1024)
print(f"received '{response.decode('utf-8')}'")

s.close()
