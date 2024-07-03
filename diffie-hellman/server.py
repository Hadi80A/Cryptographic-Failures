import socket
import random
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys


def is_prime(n, k=10):
    """Miller-Rabin primality test"""
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1:
            return True
        for _ in range(s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1

    s = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        if not check(a, s, d, n):
            return False
    return True


def generate_large_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p


def generate_dh_parameters():
    key_size = 128
    p = generate_large_prime(key_size)
    g = 2
    return p, g


def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    p, g = generate_dh_parameters()
    print(f"P:{p}")
    print(f'g:{g}')
    private_key = int.from_bytes(get_random_bytes(16), sys.byteorder)
    A = pow(g, private_key, p)
    conn.send(int.to_bytes(g, 1024, sys.byteorder))
    conn.send(int.to_bytes(p, 1024, sys.byteorder))
    conn.send(int.to_bytes(A, 1024, sys.byteorder))
    nonce = get_random_bytes(8)
    conn.send(nonce)

    B = conn.recv(1024)
    B = int.from_bytes(B, sys.byteorder)
    shared_key = pow(B, private_key, p)
    print(f'shared_key:{shared_key}')

    shared_key = int.to_bytes(shared_key, 16, sys.byteorder)

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
