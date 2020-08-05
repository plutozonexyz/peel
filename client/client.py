import socket
import pgpy
import sys
import os
import tarfile
from conf import *

HEADSIZE = 20
FILENMSIZE = 100

def decrypt_tar(enfile, passphrase):
    enc_tar = pgpy.PGPMessage.from_file('./rx/enc/'+enfile+'.tar.pgp')
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    with key.unlock(passphrase):
        os.mkdir('./rx/dec/'+enfile)
        os.write('./rx/dec/'+enfile+'.tar', str(key.decrypt(enc_tar)))
        tarfile.open('./rx/dec/'+enfile+'.tar', 'r').extractall('./rx/dec/'+enfile)
    print(f"Success in decrypting message {enfile}!")


def firsttime():
    os.mkdir('./rx')
    os.mkdir('./tx')
    os.mkdir('./rx/enc')
    os.mkdir('./rx/dec')
    os.mkdir('./tx/enc')
    os.mkdir('./tx/dec')
    print("Directories created!")

def fetch_msgs(host, passphrase):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, 293))
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    key.unlock(passphrase)
    msg = "FETCH "+USRNM, key.sign("MSGS"))
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
    recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
    recvmsg = sock.recv(recvhead).decode("UTF-8")
    if 'ERROR' in recvmsg[10:]:
        if recvmsg[-10:] == '1':
            print(f"No messages avalible for {USRNM}.")
        else:
            print(f"Got error code {recvmsg[-10:]}.")
    elif 'RECVMSG' in recvmsg[10:]:
        print(f"You have {recvmsg[-10:]} new message(s)!")
        for i in range(int(recvmsg[-10:])):
            recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
            recvfilenm = sock.recv(FILENMSIZE).decode("UTF-8").strip([' ', '\n'])
            os.write('./rx/enc/'+recvfilenm+'.tar.pgp', sock.recv(recvhead))
            print(f"MSG: {recvfilenm}")
        print("Done!")

