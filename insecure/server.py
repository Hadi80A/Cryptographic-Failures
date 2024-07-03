import socket
import random
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys


def xor(key1, key2):
    k1 = int.from_bytes(key1, sys.byteorder)
    k2 = int.from_bytes(key2, sys.byteorder)
    x = k1 ^ k2
    return int.to_bytes(x, 16, sys.byteorder)


# conn=None
def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    server_key = get_random_bytes(16)
    nonce = get_random_bytes(8)
    conn.send(server_key)
    conn.send(nonce)
    client_key = conn.recv(1024)
    shared_key = xor(server_key, client_key)
    print(f'key:{int.from_bytes(shared_key, sys.byteorder)}')
    receive_thread = threading.Thread(target=receive_messages, args=(conn, shared_key, nonce))
    receive_thread.start()
    cipher = AES.new(shared_key, AES.MODE_CTR, nonce=nonce)
    while True:
        message = input().encode()
        ciphertext = cipher.encrypt(message)
        conn.send(ciphertext)


def receive_messages(sock, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    while True:
        data = sock.recv(1024)
        if not data:
            break
        message = cipher.decrypt(data)
        print("Received: ", message.decode())


if __name__ == "__main__":
    server()
