import queue
import socket
import random
import struct
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

x = 5
z = 104729
info = b"handshake"
fifo_queue = queue.Queue()


def hkdf_derive_key(shared_int):
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info
    )
    return hkdf.derive(shared_bytes)


def recv_msg(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket connection broken")
        buf += chunk
    return buf


def file_writer():
    while True:
        message = fifo_queue.get()

        with open("server_output.txt", "a") as f:
            f.write(message)
        fifo_queue.task_done()


def handle_thread(conn):
    try:
        secret = random.randint(2, z - 2)
        public = pow(x, secret, z)

        conn.send(str(public).encode())
        client_public = int(conn.recv(1024).decode())
        conn.send(b'ACK')
        shared_secret = pow(client_public, secret, z)

        key = hkdf_derive_key(shared_secret)
        aesgcm = AESGCM(key)

        header = recv_msg(conn, 8)
        nonce_len = int.from_bytes(header[:2], "big")
        ct_len = int.from_bytes(header[2:6], "big")
        tag_len = int.from_bytes(header[6:], "big")

        payload = recv_msg(conn, nonce_len + ct_len + tag_len)
        nonce = payload[:nonce_len]
        ciphertext = payload[nonce_len:nonce_len + ct_len]
        tag = payload[nonce_len + ct_len:]

        ct_tag = ciphertext + tag

        try:
            plaintext = aesgcm.decrypt(nonce, ct_tag, associated_data=None)
            client_id = struct.unpack(">I", plaintext[:4])[0]
            message = plaintext[4:].decode()
            formatted_message = f"{client_id}: {message}\n"
            fifo_queue.put(formatted_message)

        except Exception as e:
            print("Decryption failed: ", e)

    except Exception as e:
        print("Thread error: ", e)
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9999))
    server.listen()
    writer = threading.Thread(target=file_writer, daemon=True)
    writer.start()

    while True:
        try:
            conn, addr = server.accept()
            thread = threading.Thread(target=handle_thread, args=(conn,))
            thread.start()
        except Exception as e:
            print("Error: ", e)


# Add analytics like throughput and queue time

main()
