# import required deps
import socket
import pgpy
import ssl
import os
from datetime import date

# edit this, it's a placeholder hostname to check whether a client is external
hostname = 'example.net'

# ports for communicating between server-client and server-server
clientport = 2930
serverport = 2931

# headersize describes how many digits the header saying the size of the message is.
HEADSIZE = 100

# ssl location for secure connections and authentication
cert_location = './ssl/cert.pem'
key_location = './ssl/key.pem'

def send_msg(sock, msg):
    sock.send(bytes(f"{len(msg):<{HEADSIZE}}{msg}", 'UTF-8'))

# define function for listening for clients
def client_listen():
    while True:
        print("Waiting for clients on "+clientport)
