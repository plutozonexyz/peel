import socket
import pgpy
from sys import argv
import os
import tarfile
import hashlib
from datetime import timedelta
from datetime import date
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
    with key.unlock(passphrase):
        sig = key.sign("MSGS")
    msg = "FETCH "+USRNM, sig
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
    with key.unlock(passphrase):
        sig = key.sign(to_addr)
    msg = "GETKEY "+to_addr
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
    recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
    pubkey_rec = pgpy.PGPKey()
    pubkey_rec.parse(sock.recv(recvhead))
    msg = "SEND "+USRNM, sig
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
    key.protect(input("Password for new private key: "), SymmetricKeyAlgorithm, HashAlgorithm)
    if os.path.exists('./keys/mine/private.key'):
        os.rename('./keys/mine/private.key' './keys/mine/private'+date.today()+'.key')
    if os.path.exists('./keys/mine/public.key'):
        os.rename('./keys/mine/public.key' './keys/mine/public'+date.today()+'.key')
    open('./keys/mine/private.key').write(bytes(key))
    open('./keys/mine/public.key').write(bytes(key.pubkey))
    print("Done!\nKey Expires in: 32 days\nDon't forget to run the 'keypub' command to publish your keys to the server!\nNOTE: On your first key creation, you must contact the server admin to manually publish your key.")


def keypub(passphrase):
    print("Publishing Keys...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, 293))
    msg = "KEYPUB "+USRNM, 
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}")
    recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
    recvmsg = sock.recv(recvhead).decode("UTF-8")
    recvmsgf = recvmsg.split(' ')
    if recvmsgf[0] == "VERIFY":
        with key.unlock(passphrase):
            sig = key.sign(recvmsgf[1])
        msg = "VERIFY "+sig 
        msghead = len(msg)
        sock.send(f"{msghead:<{HEADSIZE}}{msg}")
        recvhead = int(sock.recv(HEADSIZE).decode("UTF-8"))
        recvmsg = sock.recv(recvhead).decode("UTF-8")
        recvmsgf = recvmsg.split(' ')
        if recvmsgf[0] == "OK":
            msg = open('./keys/mine/public.key').read() 
            msghead = len(msg)
            sock.send(f"{msghead:<{HEADSIZE}}{msg}")
            print("Keys published!")
    else:
        print("ERROR")

