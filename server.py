import queue
import socket
import random
import struct
import time
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

x = 5
z = 371662676846312883483907188498078214933572966194890753667383346189030426715277379776687041516615304758100835966357854128119713434016176898555346248406356694358308969747442012224913645866311419936801524325041399752525593835769048354608752886142486903454777269025620009891456271353293029278665976868347
info = b"handshake"
write_queue = queue.Queue()
decryption_time = []
diffie_time = []
total_amt_threads = 1000
stats_lock = threading.Lock()


def stats(total_time):
    total_decryption_time = sum(decryption_time)
    average_decryption_time = total_decryption_time / len(decryption_time)
    total_diffie_time = sum(diffie_time)
    average_diffie_time = total_diffie_time / len(diffie_time)

    total_ops = len(decryption_time)

    print(f"Total runtime: {total_time}\n"
          f"Throughput: {total_ops / total_time}\n"
          f"Total key exchange time: {total_diffie_time}\n"
          f"Average per thread key exchange time: {average_diffie_time}\n"
          f"Total decryption time: {total_decryption_time}\n"
          f"Average per thread decryption time: {average_decryption_time}")


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
    count = 0
    with open("server_output.txt", "a") as f:
        while count < total_amt_threads:
            message = write_queue.get()
            f.write(message)
            write_queue.task_done()
            count += 1


def handle_thread(conn):
    try:
        agreed_vals = f"{x},{z}"
        conn.send(agreed_vals.encode())
        conn.recv(1024)

        diffie_start = time.thread_time()
        secret = random.randint(2, z - 2)
        public = pow(x, secret, z)
        conn.send(str(public).encode())
        client_public = int(conn.recv(1024).decode())
        conn.send(b'ACK')
        shared_secret = pow(client_public, secret, z)
        diffie_total = time.thread_time() - diffie_start
        with stats_lock:
            diffie_time.append(diffie_total)

        AES_start = time.thread_time()
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
            AES_total = time.thread_time() - AES_start
            with stats_lock:
                decryption_time.append(AES_total)
            client_id = struct.unpack(">I", plaintext[:4])[0]
            message = plaintext[4:].decode()
            formatted_message = f"{client_id}: {message}\n"
            write_queue.put(formatted_message)

        except Exception as e:
            print("Decryption failed: ", e)

    except Exception as e:
        print("Thread error: ", e)
    finally:
        conn.close()


def main():
    threads = []
    thread_count = 0
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9999))
    server.listen(total_amt_threads + 50)
    writer = threading.Thread(target=file_writer, daemon=True)
    writer.start()

    start_time = time.process_time()
    while thread_count < total_amt_threads:
        try:
            conn, addr = server.accept()
            thread_count += 1
            thread = threading.Thread(target=handle_thread, args=(conn,))
            threads.append(thread)
            thread.start()
        except Exception as e:
            print("Error: ", e)

    for t in threads:
        t.join()

    end_time = time.process_time()

    stats(end_time - start_time)
    writer.join()


main()
