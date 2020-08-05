import socket
import pgpy
import sys
import os
import tarfile

def decrypt_tar(enfile, passphrase):
    enc_tar = pgpy.PGPMessage.from_file('./rx/enc/'+enfile)
    key,_ = pgpy.PGPKey.from_file('./keys/mine/privkey.key')
    with key.unlock(passphrase):
        os.mkdir('./rx/dec/'+enfile[:-8])
        os.write('./rx/dec/'+enfile[:-4], str(key.decrypt(enc_tar)))
        tarfile.open('./rx/dec/'+enfile[:-4], 'r').extractall('./rx/dec/'+enfile[:-8])


def firsttime():
    os.mkdir('./rx')
    os.mkdir('./tx')
    os.mkdir('./rx/enc')
    os.mkdir('./rx/dec')
    os.mkdir('./tx/enc')
    os.mkdir('./tx/dec')

