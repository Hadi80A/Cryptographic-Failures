import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys

def client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 12345))

    private_key = int.from_bytes(get_random_bytes(16), sys.byteorder)

    g=int.from_bytes(client_socket.recv(1024), sys.byteorder)
    p=int.from_bytes(client_socket.recv(1024), sys.byteorder)
    A = int.from_bytes(client_socket.recv(1024), sys.byteorder)

    B = pow(g, private_key,p)

    client_socket.send(int.to_bytes(B, 1024, sys.byteorder))

    shared_key = pow(A, private_key,p)
    print(f'shared_key:{shared_key}')
    shared_key=int.to_bytes(shared_key, 16,sys.byteorder)

    nonce=client_socket.recv(1024)

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
