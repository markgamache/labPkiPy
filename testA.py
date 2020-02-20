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



syntax = "The stuff you type"

class Mode(Enum):
    NewRootCA = 1
    NewSubCA = 2
    NewLeaf = 3

def newRSAKeyPair():
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    return key

def readPemKeyFile(fileIn, passphrase = None):
    if os.path.isfile:
        f = open(fileIn, "rb")
        public_pem_data = f.read()
        f.close()

        if passphrase == None:
            key = load_pem_public_key(public_pem_data, backend=default_backend())
        else:
            key = load_pem_public_key(public_pem_data, passphrase ,  backend=default_backend())

        return key
    else:
        throw( "that ain't no file")


def keyToPemFile(keyIn, fileName, passphrase):
    
    if passphrase != None:
        with open(fileName, "wb") as f:
            f.write(keyIn.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(bytes( passphrase, 'utf-8')),
            ))
    else:
        with open(fileName, "wb") as f:
            f.write(keyIn.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()),
            )

def createNewRootCaCert(cnIn, keyIn, certFileName):
    subject = issuer = x509.Name([
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
     x509.NameAttribute(NameOID.COMMON_NAME, (cnIn)),
    ])
    cert = x509.CertificateBuilder().subject_name(
     subject
    ).issuer_name(
     issuer
    ).public_key(
     keyIn.public_key()
    ).serial_number(
     x509.random_serial_number()
    ).not_valid_before(
     datetime.datetime.utcnow()
    ).not_valid_after(
     # Our certificate will be valid for 10 days
     datetime.datetime.utcnow() + datetime.timedelta(weeks=1000)
    ).sign(keyIn, hashes.SHA256(), default_backend())
    # Write our certificate out to disk.
    with open(certFileName, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def createNewRootCA(shortName: str, passphrase = None):
    
    if passphrase != None:
        passphrase = (passphrase)

    #create the folder
    thePath = (Path( localPath)) / shortName
    os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair()
    keyToPemFile(thisOneKey, thePath / "key.pem", passphrase)

    createNewRootCaCert(shortName, thisOneKey, thePath / "cert.pem" )

global currentMode
currentMode = None

global targetFolder
targetFolder = None

def main(argv):
    
    try:
        opts, args = getopt.getopt(argv,"hm:n:v",list())
    except getopt.GetoptError:
        print(syntax )
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == "-n":
            #this is the new CA short name
            #need to check for folder name and if not there. if there throw. if not create foler and CA later
            pass

        elif opt == "-m":
            #mode will be MOde.whatever
            global currentMode
            if arg == Mode.NewRootCA.name:
                
                currentMode =  Mode.NewRootCA
            elif arg == Mode.NewSubCA.name:
                
                currentMode =  Mode.NewSubCA
            elif arg == Mode.NewLeaf.name:
                
                currentMode =  Mode.NewLeaf
            else:
                print("Your mode, -m must be NewRootCA, NewSubCA, or NewLeaf")
                print(syntax)
                sys.exit()

        elif opt == "-h":
            print(syntax)
            sys.exit()
        elif opt == "-v":
            global verbose
            verbose = True
        else:
            pass


    #magic begins here
    global localPath
    localPath = Path( os.path.abspath(os.path.dirname(sys.argv[0])))
    
    

    createNewRootCA("mark1")


    print("cats") 
    thisKey =  newRSAKeyPair()  

    keyToPemFile(thisKey, "nopass.pem", None)
    keyToPemFile(thisKey, "yesPass.pem", "thePass")
    


if __name__ == "__main__":
    main(sys.argv[1:])
 