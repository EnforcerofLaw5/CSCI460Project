import socket
import random

x = 5
z = 104729

secret = random.randint(2, z-2)

public = pow(x, secret, z)

client = socket.socket()
client.connect(('localhost', 9999))

bob_value = client.recv(1024).decode()
bob_value = int(bob_value)

client.send(str(public).encode())

shared_secret = pow(bob_value, secret, z)
print('Shared secret:', shared_secret)

client.close()