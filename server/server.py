import socket
import pgpy
import threading
import select

sel = select.DefaultSelector()

CCOMMPORT = 293
HEADSIZE = 20

servsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
servsock.bind(('', CCOMMPORT))
servsock.listen()

# while True:
#     msgf = f'{len(msg):<{HEADSIZE}}'+msg
#     clientsocket, address = servsock.accept()
#     print(f"connection {address} established")
#     clientsocket.send(bytes(msgf, "UTF-8"))
#     print(clientsocket.recv(1024).decode("UTF-8"))


