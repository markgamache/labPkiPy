import os
import sys
import getopt
from pathlib import Path
import shutil
import subprocess
import datetime
import time
import urllib.request
import requests
import OpenSSL
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
#from dateutil.parser import parse
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from enum import Enum


#end fucntions


global currentMode
currentMode = None

global targetFolder
targetFolder = None

global verbose
verbose = False        

global subjectCN  
subjectCN = "blank"

global signerCN  
signerCN = "blank"

global csrFile
csrFile = "blank"


def main(argv):
    
    try:
        opts, args = getopt.getopt(argv,"hm:n:vs:c:", ["mode=", "help", "name=", "signer=", "csr=", "verbose"])
    except getopt.GetoptError as optFail:
        print(optFail.msg)
        print(syntax )
        sys.exit(2)
    
    if len(args) > 0:
        print("You have an argument set that is not tied to a switch")
        print(syntax )
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-n" or opt == "--name":
            #this is the new CA short name
            #need to check for folder name and if not there. if there throw. if not create foler and CA later
            global subjectCN  
            subjectCN = arg
            

        elif opt == "--mode" or opt == "-m":
            #mode will be MOde.whatever
            global currentMode
            if arg == Mode.NewRootCA.name:
                currentMode =  Mode.NewRootCA

            elif arg == Mode.NewSubCA.name:
                currentMode =  Mode.NewSubCA

            elif arg == Mode.NewLeafTLS.name:
                currentMode =  Mode.NewLeafTLS

            elif arg == Mode.NewSubCaFromCSR.name:
                currentMode =  Mode.NewSubCaFromCSR

            elif arg == Mode.NewTlsFromCSR.name:
                currentMode =  Mode.NewTlsFromCSR

            elif arg == Mode.SignCRL.name:
                currentMode =  Mode.SignCRL

            elif arg == Mode.CreateCaCSR.name:
                currentMode =  Mode.CreateCaCSR

            elif arg == Mode.CreateTlsCsr.name:
                currentMode =  Mode.CreateTlsCsr

            else:
                print("Your mode must be NewRootCA, NewSubCA, NewSubCaFromCSR, NewTlsFromCSR, SignCRL, CreateTlsCsr, CreateCaCSR,  or NewLeafTLS")
                print(syntax)
                sys.exit()

        elif opt == "-h" or opt == "--help":
            print(syntax)
            sys.exit()

        #signer
        elif opt == "-s" or opt == "--signer":
            global signerCN  
            signerCN = arg

        #csr to sign
        elif opt == "-c" or opt == "--csr":
            #see if the file is legit
            global csrFile
            csrFile = arg


        elif opt == "-v":
            global verbose
            verbose = True
        else:
            print("{} is not a valid argument or flag".format(opt))


    #magic begins here
    global localPath
    localPath = Path( os.path.abspath(os.path.dirname(sys.argv[0])))
    
    os.system("DoCAStuff.py -m NewRootCA -n testRoot" )   

    with open((localPath / "testRoot") / "aia.txt", "w") as f:
        f.write("http://example.com/ca.crt")

    with open((localPath / "testRoot") / "cdp.txt", "w") as f:
        f.write("http://example.com/file.crl")

    
    os.system("DoCAStuff.py -m SignCRL -s testRoot" )   
        

    os.system("DoCAStuff.py -m NewSubCA -s testRoot -n testSubCA" )
    with open((localPath / "testSubCA") / "aia.txt", "w") as f:
        f.write("http://example.com/caSub.crt")

    with open((localPath / "testSubCA") / "cdp.txt", "w") as f:
        f.write("http://example.com/fileSub.crl")

    with open((localPath / "testSubCA") / "revoked.txt", "w") as f:
        f.write("1313")
    
    os.system("DoCAStuff.py -m SignCRL -s testSubCA" )   

    #easy cert
    os.system("DoCAStuff.py -m NewLeafTLS -s testSubCA -n www.example.com" )

    #create CSR and then sign csr for subCA
    os.system("DoCAStuff.py -m CreateCaCSR -n specSubCa" )  

    csrPath = (localPath / "specSubCa") / "file.csr"
    #NewSubCaFromCSR 
    os.system("DoCAStuff.py -m NewSubCaFromCSR -s testRoot -c {}".format(csrPath) )  


    #create TLS csr then sign
    os.system("DoCAStuff.py -m CreateTlsCsr -n checkout.example.com" )  

    csrPath = (localPath / "checkout.example.com") / "file.csr"
    #NewSubCaFromCSR 
    os.system("DoCAStuff.py -m NewTlsFromCSR -s specSubCa -c {}".format(csrPath) )  


    
    print("Test Passed?")

 


if __name__ == "__main__":
    main(sys.argv[1:])
 