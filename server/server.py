import socket
import pgpy
import threading
import ssl
import os

CCOMMPORT = 293
HEADSIZE = 100
cert_location = './ssl/cert.pem'
key_location = './ssl/key.pem'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversock = ssl.wrap_socket(sock, certfile=cert_location, keyfile=key_location, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL")
serversock.bind(('', CCOMMPORT))
serversock.listen()
print(f'listening on *:{CCOMMPORT}')
serversock.setblocking(False)


# while True:
#     msgf = f'{len(msg):<{HEADSIZE}}'+msg
#     clientsocket, address = servsock.accept()
#     print(f"connection {address} established")
#     clientsocket.send(bytes(msgf, "UTF-8"))
#     print(clientsocket.recv(1024).decode("UTF-8"))

# clientsocket, address = servsock.accept()


def recv_msg(client_socket):
    try:
        msg_head = int(client_socket.recv(HEADSIZE).decode("UTF-8"))
        if not len(msg_head):
            return False
        return client_socket.recv(MSGSIZE)
    except:
        return False

while True:
    def conn_listen():
        client_socket, client_address = serversock.accept()
        print(f"connection {client_address[0]}:{client_address[1]} established")
        recvd = recv_msg(client_socket).split(' ')
        if recvd[0] == 'FETCH':
            print("Fetching messages for "+recvd[1]+"...")
            