from scapy.all import *
from Crypto.Cipher import AES
from colorama import Fore
server_key = None
nonce = None
client_key = None
shared_key = None
cipher_server = None
cipher_client = None


def sniff_msg(packet):
    global cipher_server, cipher_client
    # Check if the packet is TCP and has data
    if TCP in packet and packet.haslayer(Raw):
        data = packet[Raw].load
        if packet[TCP].dport == 12345:
            message = cipher_client.decrypt(data).decode()
            print(Fore.YELLOW+f"Client: {message}")
        elif packet[TCP].sport == 12345:
            message = cipher_server.decrypt(data).decode()
            print(Fore.BLUE+f"Server: {message}")


def sniff_key(packet):
    is_server = False
    is_client = False
    global server_key
    global client_key
    global nonce
    global cipher_server, cipher_client
    if TCP in packet and packet.haslayer(Raw):
        if packet[TCP].sport == 12345:
            is_server = True
        elif packet[TCP].dport == 12345:
            is_client = True

        else:
            return

        if is_server:
            if server_key is None:
                server_key = packet[Raw].load
                print(Fore.GREEN+"[+] received server key")
            elif nonce is None:
                nonce = packet[Raw].load
                print(Fore.GREEN+"[+] received nonce")

        if is_client and client_key is None:
            client_key = packet[Raw].load
            print(Fore.GREEN+"[+] received client key")

        if not None in [server_key, client_key, nonce]:
            key = xor(server_key, client_key)
            cipher_server = AES.new(key, AES.MODE_CTR, nonce=nonce)
            cipher_client = AES.new(key, AES.MODE_CTR, nonce=nonce)
            print(Fore.MAGENTA+f"shared key:{int.from_bytes(key,sys.byteorder)}")


def xor(key1, key2):
    k1 = int.from_bytes(key1, sys.byteorder)
    k2 = int.from_bytes(key2, sys.byteorder)
    x = k1 ^ k2
    return int.to_bytes(x, 16, sys.byteorder)


def sniff_packets(packet):
    global cipher_server
    if cipher_server is None:
        sniff_key(packet)
    else:
        sniff_msg(packet)


def main():
    print(Fore.GREEN+"[*] Sniffing packets...")
    sniff(filter="tcp", prn=sniff_packets, iface=conf.loopback_name)


if __name__ == "__main__":
    main()
