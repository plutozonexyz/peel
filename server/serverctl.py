import pgpy
import sys
import os

if len(sys.argv) == 1:
    print('''COMMANDS:
INIT
ADDUSR <PUBLIC_KEY_FILE_PATH (IN QUOTES)>
RMUSR <USERNAME>
''')
elif sys.argv[1].upper() == 'INIT':
    os.mkdir('./ssl')
    os.mkdir('./pubkeys')
    print("You will have to make your own SSL cert and private key. Put these under './ssl/cert.pem' and './ssl/key.pem'.")
elif sys.argv[1].upper() == 'RMUSR':
    if len(sys.argv) == 3:
        os.remove('./pubkeys/'+sys.argv[2])
        print("Done!")
    else:
        print("Please specify one user.")
elif sys.argv[1].upper() == 'ADDUSR':
    if len(sys.argv) == 3:
        