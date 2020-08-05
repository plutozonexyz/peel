import socket
import pgpy
from sys import argv
import os
import tarfile
import hashlib
from datetime import timedelta
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
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


def init():
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
    recvmsgf = recvmsg.split(' ')
    if 'ERROR' in recvmsgf[0]:
        if recvmsgf[1] == '1':
            print(f"No messages avalible for {USRNM}.")
        else:
            print(f"Got error code {recvmsg[1]}.")
    elif 'RECVMSG' in recvmsgf[0]:
        print(f"You have {recvmsgf[1]} new message(s)!")
        for i in range(int(recvmsgf[1])):
            recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
            recvfilenm = sock.recv(FILENMSIZE).decode("UTF-8").strip([' ', '\n'])
            os.write('./rx/enc/'+recvfilenm+'.tar.pgp', sock.recv(recvhead))
            print(f"MSG: {recvfilenm}")
        print("Done!")

def compose_msg(body_file, to_addr, subject, passphrase, attachment):
    shatar = hashlib.sha256(subject).hexdigest()
    f = open(body_file, 'r')
    f2 = open('./tx/dec/'+shatar+'/msg.txt', 'w')
    f2.write("SUBJECT: "+subject+"\n\n"+f.read())
    f2.close()
    f.close()

    tarfile.open('./tx/dec/'+shatar+'.tar', 'x')
    os.mkdir('./tx/dec/'+shatar)
    tf = tarfile.open('./tx/dec/'+shatar+'.tar', 'w')
    if len(attachment) > 0:
        os.mkdir('./tx/dec/'+shatar+'/attach')
        for i in range(len(attachment)):
            fname = attachment[i].split("/").split("\\")
            att_file = open(attachment); att_dest_file = open('./tx/dec/'+shatar+'/'+fname)
            att_dest_file.write(att_file.read())
            att_dest_file.close(); att_file.close()
        tf.addfile('./tx/dec/'+shatar+'/attach')

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, 293))
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    key.unlock(passphrase)
    msg = "GETKEY "+to_addr
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
    recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
    pubkey_rec = pgpy.PGPKey()
    pubkey_rec.parse(sock.recv(recvhead))
    msg = "SEND "+USRNM, key.sign(to_addr)
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
    recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
    recvmsg = sock.recv(recvhead).decode("UTF-8")
    recvmsgf = recvmsg.split(' ')
    if recvmsgf[0] == "OK":
        msghead = len(bytes())
        sock.send(f"{msghead:<{HEADSIZE}}"+pubkey_rec.encrypt(open('./tx/dec/'+shatar+'.tar', 'r').read()))
    else:
        print("ERROR")
    print("Done!")
    

def keygen():
    print("Generating Keys...")
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new(USRNM)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed],
        key_expired=timedelta(days=32))

    key.