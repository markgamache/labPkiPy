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

def newRSAKeyPair(size = 2048):
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,
    backend=default_backend()
    )
    return key

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

def readPemPrivateKeyFromFile(fileIn, passphrase = None):
    if os.path.isfile:
        f = open(fileIn, "rb")
        public_pem_data = f.read()
        f.close()

        key = cryptography.hazmat.primitives.serialization.load_pem_private_key(public_pem_data, passphrase ,  backend=default_backend())

        return key
    else:
        raise( "that ain't no file")

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
    ).add_extension(x509.BasicConstraints(ca= True, path_length= None), critical = True).sign(keyIn, hashes.SHA256(), default_backend())
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
    thisOneKey = newRSAKeyPair(4096)
    keyToPemFile(thisOneKey, thePath / "key.pem", passphrase)

    createNewRootCaCert(shortName, thisOneKey, thePath / "cert.pem" )

def createNewSubCA(subjectShortName: str, issuerShortName: str, subjectPassphrase = None, issuerPassphrase = None):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( localPath)) / subjectShortName
    os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(4096)
    keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)

    issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    theSubCACert = signSubCaCsrWithCaKey(theCsrWeNeed, issCert, issCaKey)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.PEM))

def createNewCsr(privKeyIn, cnIn):
    thisCsr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
     x509.NameAttribute(NameOID.COMMON_NAME, cnIn), ])).sign(privKeyIn, hashes.SHA256(), default_backend())

    return thisCsr

def signSubCaCsrWithCaKey(csrIn, issuerCert, caKeyIn):
    
    #we need the CA priv Key,  CA cert to get issuer info, and the CSR
    cert = x509.CertificateBuilder().subject_name(
     csrIn.subject
    ).issuer_name(
     issuerCert.subject
    ).public_key(
     csrIn.public_key()
    ).serial_number(
     x509.random_serial_number()
    ).not_valid_before(
     datetime.datetime.utcnow()
    ).not_valid_after(
     # Our certificate will be valid for 10 days
     datetime.datetime.utcnow() + datetime.timedelta(weeks=500)
    ).add_extension(x509.BasicConstraints(ca= True, path_length= None), critical = True ).sign(caKeyIn, hashes.SHA256(), default_backend())

    return cert

def signTlsCsrWithCaKey(csrIn, issuerCert, caKeyIn):
    
    #we need the CA priv Key,  CA cert to get issuer info, and the CSR
    cert = x509.CertificateBuilder().subject_name(
     csrIn.subject
    ).issuer_name(
     issuerCert.subject
    ).public_key(
     csrIn.public_key()
    ).serial_number(
     x509.random_serial_number()
    ).not_valid_before(
     datetime.datetime.utcnow()
    ).not_valid_after(
     # Our certificate will be valid for 10 days
     datetime.datetime.utcnow() + datetime.timedelta(weeks=500)
    ).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=True 
    ).add_extension(x509.BasicConstraints(ca= False, path_length= None), critical = True).sign(caKeyIn, hashes.SHA256(), default_backend())

    return cert

def createNewTlsCert(subjectShortName: str, issuerShortName: str, subjectPassphrase = None, issuerPassphrase = None):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( localPath)) / subjectShortName
    os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(2048)
    keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)

    issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    theTlsCert = signTlsCsrWithCaKey(theCsrWeNeed, issCert, issCaKey)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))


def readCertFile(fileNameIn : Path):
    
    if os.path.isfile(fileNameIn):
        with open(fileNameIn, "rb") as f:
            myDat = f.read()
            f.close()
        try:
            theCert = cryptography.x509.load_pem_x509_certificate(myDat, backend=default_backend())
            return theCert
        except Exception as exCer:
            print(exCer)
    else:
        print("{} is not a file".format(fileNameIn))
        raise


global currentMode
currentMode = None

global targetFolder
targetFolder = None

def main(argv):
    
    try:
        opts, args = getopt.getopt(argv,"hm:n:v", ["mode=","help", "name="])
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
            pass

        elif opt == "--mode" or opt == "-m":
            #mode will be MOde.whatever
            global currentMode
            if arg == Mode.NewRootCA.name:
                
                currentMode =  Mode.NewRootCA
            elif arg == Mode.NewSubCA.name:
                
                currentMode =  Mode.NewSubCA
            elif arg == Mode.NewLeaf.name:
                
                currentMode =  Mode.NewLeaf
            else:
                print("Your mode must be NewRootCA, NewSubCA, or NewLeaf")
                print(syntax)
                sys.exit()

        elif opt == "-h" or opt == "--help":
            print(syntax)
            sys.exit()
        elif opt == "-v":
            global verbose
            verbose = True
        else:
            print("{} is not a valid argument or flag".format(opt))


    #magic begins here
    global localPath
    localPath = Path( os.path.abspath(os.path.dirname(sys.argv[0])))
    
    createNewRootCA("Mark Trust Some Assurance Root CA")

    #use the mark1 CA to sign a sub
    createNewSubCA("Mark Trust Some Assurance Int CA", "Mark Trust Some Assurance Root CA", None, None )

    createNewSubCA("Mark Trust TLS Issuer 01", "Mark Trust Some Assurance Int CA", None, None )
    createNewSubCA("Mark Trust TLS Issuer 02", "Mark Trust Some Assurance Int CA", None, None )


    createNewTlsCert("www.markgamache.com", "Mark Trust TLS Issuer 01", None, None)
    createNewTlsCert("checkout.markgamache.com", "Mark Trust TLS Issuer 02", None, None)
    

    
    print("cats") 
    #thisKey =  newRSAKeyPair()  

    #keyToPemFile(thisKey, "nopass.pem", None)
    #keyToPemFile(thisKey, "yesPass.pem", "thePass")
    


if __name__ == "__main__":
    main(sys.argv[1:])
 