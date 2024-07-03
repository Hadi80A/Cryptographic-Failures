import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

def xor(key1, key2):
    k1 = int.from_bytes(key1, sys.byteorder)
    k2 = int.from_bytes(key2, sys.byteorder)
    x= k1 ^ k2
    return int.to_bytes(x,16,sys.byteorder)


def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    client_key = get_random_bytes(16)
    client_socket.send(client_key)

    server_key = client_socket.recv(1024)
    nonce=client_socket.recv(1024)
    shared_key = xor(server_key ,client_key)
    print(f'key:{int.from_bytes(shared_key, sys.byteorder)}')

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket, shared_key,nonce))
    receive_thread.start()
    cipher = AES.new(shared_key, AES.MODE_CTR,nonce=nonce)
    while True:
        message = input().encode()
        ciphertext = cipher.encrypt(message)
        client_socket.send(ciphertext)


def receive_messages(sock, key,nonce):
    cipher = AES.new(key, AES.MODE_CTR,nonce=nonce)
    while True:
        data = sock.recv(1024)
        if not data:
            break
        message = cipher.decrypt(data)
        print("Received: ", message.decode())


if __name__ == "__main__":
    client()
