import socket
import pgpy
import sys
import os
import tarfile
import hashlib
import ssl
from datetime import timedelta
from datetime import date
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from conf import *

HEADSIZE = 100
FILENMSIZE = 150

def decrypt_tar(enfile, passphrase):
    enc_tar = pgpy.PGPMessage.from_file('./rx/enc/'+enfile+'.tar.pgp')
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    with key.unlock(passphrase):
        os.mkdir('./rx/dec/'+enfile)
        os.write('./rx/dec/'+enfile+'.tar', str(key.decrypt(enc_tar)))
        tarfile.open('./rx/dec/'+enfile+'.tar', 'r').extractall('./rx/dec/'+enfile)
        os.remove('./rx/enc/'+enfile+'.tar.pgp')
        os.remove('./rx/dec/'+enfile+'.tar')
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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL")
    sock.connect((HOST, 293))
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private.key')
    with key.unlock(passphrase):
        sig = key.sign("MSGS")
    msg = "FETCH "+USRNM
    msghead = len(msg)
    sock.send(f"{msghead:<{HEADSIZE}}{msg}", "UTF-8")
    sock.send(f"{len(sig):<{HEADSIZE}}", "UTF-8")
    sock.send(sig)
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
            print(f"[{i}] MSG: {recvfilenm}")
        print("Done!")

def compose_msg(body_file, to_addr, subject, passphrase, attachment):
    shatar = hashlib.sha256(subject).hexdigest()
    f = open(body_file, 'r')
    f2 = open('./tx/dec/'+shatar+'/msg.txt', 'w')
    f2.write("SUBJECT: "+subject+"\nFROM: "+USRNM+"@"+HOST+"\nTO: "+to_addr+"\n\n\n"+f.read())
    f2.close()
    f.close()

    tarfile.open('./tx/dec/'+shatar+'.tar', 'x')
    os.mkdir('./tx/dec/'+shatar)
    tf = tarfile.open('./tx/dec/'+shatar+'.tar', 'w')
    if len(attachment) > 0:
        os.mkdir('./tx/dec/'+shatar+'/attach')
        for i in range(len(attachment)):
            fname = attachment[i].split("/").split("\\")
            att_file = open(attachment[i]); att_dest_file = open('./tx/dec/'+shatar+'/attach/'+fname)
            att_dest_file.write(att_file.read())
            att_dest_file.close(); att_file.close()
        tf.addfile('./tx/dec/'+shatar+'/attach')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL")
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
        arc = pubkey_rec.encrypt(open('./tx/dec/'+shatar+'.tar', 'r').read())
        msghead = len(bytes(arc))
        sock.send(f"{msghead:<{HEADSIZE}}", "UTF-8")
        sock.send(arc)
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
    key,_ = pgpy.PGPKey.from_file('./keys/mine/private'+date.today()+'.key')
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2, ciphers="ALL")
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


if len(sys.argv) == 1:
    print("Type the command 'HELP' for a list of commands.")
elif sys.argv[1].lower() == 'help':
    if len(sys.argv) == 2:
        print(f'''Type 'help [command]' for a list of arugments and what they can do.
NOTE: For all commands to work you MUST be in the same directory as the client script. Run 'dir' or 'ls' to check this in your system shell.
NOTE 2: PLEASE fill out the included config.py with the variables included. Most stuff won't work without it.
COMMAND LIST:
{'HELP':<10}Displays help.
{'INIT':<10}Creates the initial directories.
{'FETCH':<10}Retrieves new messages off the server. They are also deleted off the server once fetched.
{'COMPOSE':<10}Writes a new message and sends it.
{'KEYGEN':<10}Generates a new key pair. Reccomended to do this 2 days before your old keys expire, as your old keys will verify with the server that you are yourself.
{'KEYPUB':<10}Run this on the same day that you generated the keys. If the day changes, you will have to manually use your old keys somehow to tell the server that you are yourself.
{'DECRYPT':<10}Run this along with the filename of the .tar.pgp message archive you wish to decrypt. Do not include the file extension(s).''')
    elif len(sys.argv) == 3:
        helpsub = sys.argv[2].lower()
        if helpsub == 'help':
            print('''SYNTAX:
HELP 
    [COMMAND] Another command in the script that can be called. This is for explaining it.''')
        elif helpsub == 'init':
            print('''SYNTAX:
INIT''')
        elif helpsub == 'fetch':
            print('''SYNTAX:
FETCH''')
        elif helpsub == 'compose':
            print('''SYNTAX:
COMPOSE
    <BODY FILE> Location of the .txt file containing the body of the message; in quotes.
    <TO ADDR> Recipient's address; in quotes. typically in the format of '{user.name}@{domain.net}'
    <SUBJECT> Subject line; in quotes.
    [ATTACHMENT 1] Full system path to the attachment; in quotes.
    [ATTACHMENT 2] See above.
    [ATTACHMENT etc...]''')
        elif helpsub == 'keygen':
            print('''SYNTAX:
KEYGEN''')
        elif helpsub == 'keypub':
            print('''SYNTAX:
KEYPUB''')
        elif helpsub == 'decrypt':
            print('''SYNTAX:
DECRYPT
    <NAME> Filename of message archive needed to be decrpyted. Do not include extensions.''')
        else:
            print("That command does not exist.")
    else:
        print("I don't understand.")

elif sys.argv[1].lower() == 'decrypt':
    if len(sys.argv) == 3:
        decrypt_tar(sys.argv[2], input("Password: "))
    else:
        print("Please input one message name to decrypt!")
elif sys.argv[1].lower() == 'fetch':
    fetch_msgs(input("Password: "))
elif sys.argv[1].lower() == 'init':
    init()
elif sys.argv[1].lower() == 'compose':
    if len(sys.argv) < 5:
        print("See 'HELP COMPOSE' for creating a message.")
    else:
        attachment = []
        if len(sys.argv) > 5:
            for i in range(len(sys.argv) - 5):
                attachment.append(i)
        compose_msg(sys.argv[2], sys.argv[3], sys.argv[4], input("Password: "), attachment)
elif sys.argv[1].lower() == 'keygen':
    keygen()
elif sys.argv[1].lower() == 'keypub':
    keypub(input("Password: "))
else:
    print("Command not understood.")
