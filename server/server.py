import socket
import pgpy
import threading
import select


CCOMMPORT = 293
HEADSIZE = 20

serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        msg_head = client_socket.recv(HEADSIZE)
        if not len(msg_head):
            return False
        MSGSIZE = int(msg_head.decode("UTF-8"))
        return {"header": msg_head, "data": client_socket.recv(MSGSIZE)}
    except:
        return False

while True:
    def conn_listen():
        client_socket, client_address = serversock.accept()
        print(f"connection {client_address[0]}:{client_address[1]} established")

