import socket
import random
import os
import struct
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

x = 5
z = 104729
info = b"handshake"
total_amt_threads = 2000
start_barrier = threading.Barrier(total_amt_threads)


def hkdf_derive_key(shared_int):
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_bytes)


def run_client(thread_id):

    start_barrier.wait()

    secret = random.randint(2, z - 2)
    public = pow(x, secret, z)

    client = socket.socket()
    client.connect(('localhost', 9999))

    server_value = client.recv(1024).decode()
    server_value = int(server_value)

    client.send(str(public).encode())
    client.recv(1024)

    shared_secret = pow(server_value, secret, z)

    aes_key = hkdf_derive_key(shared_secret)
    aesgcm = AESGCM(aes_key)

    id_bytes = struct.pack(">I", thread_id)
    text_msg = b"Hello, this is a secret!"

    final_plaintext = id_bytes + text_msg
    nonce = os.urandom(12)

    encrypted_data = aesgcm.encrypt(nonce, final_plaintext, associated_data=None)

    tag = encrypted_data[-16:]
    ciphertext = encrypted_data[:-16]

    header = struct.pack(">HIH", len(nonce), len(ciphertext), len(tag))

    payload = header + nonce + ciphertext + tag
    client.send(payload)

    client.close()


def main():
    threads = []

    for i in range(total_amt_threads):
        thread = threading.Thread(target=run_client, args=(i + 1,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    print("Client threads sent")


main()
