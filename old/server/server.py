import socket
import pgpy
import threading
import ssl
import os
from datetime import date

CCOMMPORT = 2930
HEADSIZE = 100
FILENMSIZE = 150
cert_location = './ssl/cert.pem'
key_location = './ssl/key.pem'

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversock = ssl.wrap_socket(sock, certfile=cert_location, keyfile=key_location, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL")
serversock.bind(('', CCOMMPORT))
serversock.listen()
print(f'listening on *:{CCOMMPORT}')
# serversock.setblocking(False)


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
        return client_socket.recv(msg_head)
    except:
        return False

def send_msg(client_socket, msg):
    try:
        msgf = f'{len(msg):<{HEADSIZE}}'+msg
        serversock.send(bytes(msgf, "UTF-8"))
    except:
        return False

def recv_file(client_socket):
    try:
        msg_head = int(client_socket.recv(HEADSIZE).decode("UTF-8"))
        if not len(msg_head):
            return False
        return client_socket.recv(msg_head).decode("UTF-8")
    except:
        return False

def send_file(client_socket, file):
    try:
        # msgf = f'{len(file):<{HEADSIZE}}'+msg
        # serversock.send(msgf, "UTF-8")
        msghead = len(bytes(file))
        serversock.send(bytes(f"{msghead:<{HEADSIZE}}", "UTF-8"))
        serversock.send(bytes(file))
    except:
        return False

while True:
    client_socket, client_address = serversock.accept()
    with client_socket:
        print(f"connection {client_address[0]}:{client_address[1]} established")
        try:
            recvd = recv_msg(client_socket).split(' ')
        except:
            client_socket.close()
        if recvd[0] == 'FETCH':
            print("Fetching messages for "+recvd[1]+"...")
            key,_ = pgpy.PGPKey.from_file('./pubkeys/'+recvd[1])
            try:
                sig = recv_file(client_socket)
            except:
                send_msg(client_socket, "ERROR SIG_INVALID")
                break
            if key.decypt(sig) == "MSGS":
                dirlist = os.listdir('./msgs/'+recvd[1])
                num = len(dirlist)
                if num == 0:
                    send_msg(client_socket, 'ERROR 1')
                else:
                    send_msg(client_socket, "RECVMSG "+num)
                    for i in num:
                        f = dirlist[i]
                        fr = open(f, 'r').read()
                        msgf = f'{len(fr):<{HEADSIZE}}{f:<{FILENMSIZE}}'
                        client_socket.send(bytes(msgf, "UTF-8"))
                        client_socket.send(bytes(fr, "UTF-8"))
        elif recvd[0] == 'KEYPUB':
            if recvd[1] in os.listdir('./pubkeys'):
                dd = date.today()
                send_msg(client_socket, "VERIFY "+dd)
                msg_head = int(client_socket.recv(HEADSIZE).decode("UTF-8"))
                sig = client_socket.recv(HEADSIZE).decode("UTF-8")
                key,_ = pgpy.PGPKey.from_file('./pubkeys/'+recvd[1])
                
                try:
                    if key.verify(dd, sig):
                        send_msg(client_socket, 'OK')
                        kf = recv_msg(client_socket).decode("UTF-8")
                        open('./pubkeys/'+recvd[1], 'w+').write(kf)
                    else:
                        send_msg(client_socket, 'ERROR SIG_INVALID')
                except:
                    send_msg(client_socket, 'ERROR SIG_INVALID')
        elif recvd[0] == 'GETKEY':
            if recvd[1] in os.listdir('./pubkeys'):
                send_msg(client_socket, 'OK')
                f = './pubkeys/'
                fr = open(f, 'r').read()
                msgf = f'{len(fr):<{HEADSIZE}}'
                client_socket.send(bytes(msgf, "UTF-8"))
                client_socket.send(bytes(fr, "UTF-8"))
                recvd_two = recv_msg(client_socket).split(' ')
                if recvd_two[0] in os.listdir('./pubkeys'):
                    send_msg(client_socket, 'OK')
                    shatar = recv_msg(client_socket)
                    f3 = recv_file(client_socket).decode("UTF-8")
                    open(f'./msgs/{recvd_two[0]}/{shatar}', 'w+').write(f3)
                else:
                    send_msg(client_socket, "ERROR USR_NOT_FOUND")
            else:
                send_msg(client_socket, "ERROR USR_NOT_FOUND")
        client_socket.close()
