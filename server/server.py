import socket
import pgpy
import threading
import select


CCOMMPORT = 293
HEADSIZE = 20

servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
servsock.bind(('', CCOMMPORT))
servsock.listen()
print(f'listening on *:{CCOMMPORT}'))
serversock.setblocking(False)

sel.register(serversock, selectors.EVENT_READ, accept)


# while True:
#     msgf = f'{len(msg):<{HEADSIZE}}'+msg
#     clientsocket, address = servsock.accept()
#     print(f"connection {address} established")
#     clientsocket.send(bytes(msgf, "UTF-8"))
#     print(clientsocket.recv(1024).decode("UTF-8"))

# clientsocket, address = servsock.accept()

sockets_list = ''

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
    read_sockets, _, exception_sock = select.select(sockets_list, [], sockets_list)
    
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = serversock.accept()
            user = recv_msg(client_socket)
            if user is False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = user
            print(f"connection {client_address[0]}:{client_address[1]} established")
