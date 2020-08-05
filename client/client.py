import socket
import pgpy
import sys
import os
import tarfile
import hashlib
from conf import *

HEADSIZE = 20
FILENMSIZE = 150

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

def fetch_msgs(passphrase):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, 293))
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    key.unlock(passphrase)
    msg = "FETCH "+USRNM, key.sign("MSGS")
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
    recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
    recvmsg = sock.recv(recvhead).decode("UTF-8")
    if 'ERROR' in recvmsg[HEADER:]:
        if recvmsg[-HEADER:] == '1':
            print(f"No messages avalible for {USRNM}.")
        else:
            print(f"Got error code {recvmsg[-HEADER:]}.")
    elif 'RECVMSG' in recvmsg[HEADER:]:
        print(f"You have {recvmsg[-HEADER:]} new message(s)!")
        for i in range(int(recvmsg[-HEADER:])):
            recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
            recvfilenm = sock.recv(FILENMSIZE).decode("UTF-8").strip([' ', '\n'])
            os.write('./rx/enc/'+recvfilenm+'.tar.pgp', sock.recv(recvhead))
            print(f"MSG: {recvfilenm}")
        print("Done!")

def compose_msg(body_file, attachment, to_addr, subject, passphrase):
    shatar = hashlib.sha256(subject).hexdigest()
    tarfile.open('./tx/dec/'+shatar+'.tar', x)
    tf = tarfile.open('./tx/dec/'+shatar+'.tar', w)
    for i in range(len(attachment)):
        tf.addfile(attachment[i])
        
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, 293))
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    key.unlock(passphrase)
    msg = "SEND "+USRNM, key.sign(to_addr)
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
