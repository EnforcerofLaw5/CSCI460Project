import socket
import random

x = 5
z = 104729

secret = random.randint(2, z-2)
public = pow(x, secret, z)

server = socket.socket()
server.bind(('localhost', 9999))

server.listen(1)
print('Bob listening...')

conn, addr = server.accept()
conn.send(str(public).encode())

alice_value = conn.recv(1024).decode()

shared_secret = pow(alice_value, secret, z)
print('Shared secret:', shared_secret)

conn.close()
server.close()