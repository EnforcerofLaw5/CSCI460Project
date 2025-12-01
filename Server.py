import socket
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

x = 5
z = 104729

def hkdf_derive_key(shared_int, info, bytes = b"dh-aes-gcm"):
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_bytes)

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
key = hkdf_derive_key(shared_secret)
aesgcm = AESGCM(key)

def recv_msg(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket connection broken")
        buf += chunk
    return buf

header = recv_msg(conn, 2 + 4 + 2)
nonce_len = int.from_bytes(header[:2], "big")
ct_len = int.from_bytes(header[2:4], "big")
tag_len = int.from_bytes(header[4:6], "big")

payload = recv_msg(conn, nonce_len + ct_len + tag_len)
nonce = payload[:nonce_len]
ciphertext = payload[nonce_len:nonce_len + ct_len]
tag = payload[nonce_len + ct_len:]

ct_tag = ciphertext + tag

try:
    plaintext = aesgcm.decrypt(nonce, ct_tag, associated_data=None)
    print("Bob decrypted message: ", plaintext.decode())
except Exception as e:
    print("Decryption failed: ", e)

conn.close()
server.close()