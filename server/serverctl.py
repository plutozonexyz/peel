import pgpy
import sys
import os

if len(sys.argv) == 1:
    print('''COMMANDS:
INIT
ADDUSR <PUBLIC_KEY_FILE_PATH (IN QUOTES)> <USERNAME>
RMUSR <USERNAME>
''')
elif sys.argv[1].upper() == 'INIT':
    os.mkdir('./ssl')
    os.mkdir('./pubkeys')
    os.mkdir('./msgs')
    print("You will have to make your own SSL cert and private key. Put these under './ssl/cert.pem' and './ssl/key.pem'.")
elif sys.argv[1].upper() == 'RMUSR':
    if len(sys.argv) == 3:
        os.remove('./pubkeys/'+sys.argv[2])
        print("Done!")
    else:
        print("Please specify one user.")
elif sys.argv[1].upper() == 'ADDUSR':
    if len(sys.argv) == 4:
        key = pgpy.PGPKey.from_file(sys.argv[2])
#        usrname = pgpy.PGPUID.name(key.userids)
        usrname = sys.argv[3]
        if ' ' in usrname:
            print("No spaces allowed inside usernames!")
        else:
            open('./pubkeys/'+usrname, 'w+').write(bytes(key))
            os.mkdir('./msgs/'+usrname)
            print("Added user!")
    else:
        print("Please specify one public key.")
