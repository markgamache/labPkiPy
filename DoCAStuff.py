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
    NewLeafTLS = 3
    NewSubCaFromCSR = 4
    NewTlsFromCSR = 5
    SignCRL = 6
    CreateCaCSR = 7
    CreateTlsCsr = 8
    

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

    #also do a fun named cer verions
    fileName = getFileNameFromCert(cert)
    with open(certFileName.parent / fileName, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

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
    if os.path.isdir(thePath):
        print("{} already exists. Change the name or remove it and try again".format(thePath))
        sys.exit()
    else:
        os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(4096)
    keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)

    issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( localPath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( localPath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( localPath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( localPath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()

    theSubCACert = signSubCaCsrWithCaKey(csrIn = theCsrWeNeed, issuerCert = issCert, caKeyIn= issCaKey , cdpList= cdps, aiaList = aias , pathLen = None)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theSubCACert)
    with open(thePath / fileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.DER))

    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( localPath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.DER))


def createNewCsr(privKeyIn, cnIn):
    thisCsr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
     x509.NameAttribute(NameOID.COMMON_NAME, cnIn), ])).sign(privKeyIn, hashes.SHA256(), default_backend())

    return thisCsr

def createNewCsrTLS(privKeyIn, cnIn):
    thisCsr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.COMMON_NAME, cnIn), ])).add_extension(x509.SubjectAlternativeName([x509.DNSName(cnIn)]), critical=False  
    ).sign(privKeyIn, hashes.SHA256(), default_backend())

    return thisCsr


def getFileNameFromCert(certIn : cryptography.x509):
    
    cnPart = certIn.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    cnPart = cnPart.replace(" " , "")
    serPart = str(hex(certIn.serial_number))
    cnPart = "{}_{}.cer".format(cnPart, serPart[-6:-1]) 
    
    return cnPart
 
def signSubCaCsrWithCaKey(csrIn, issuerCert, caKeyIn, cdpList = list(), aiaList = list(), pathLen = None , hashAlgo = hashes.SHA256()):
    
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
     datetime.datetime.utcnow() + datetime.timedelta(weeks=500)
    )

    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)

    
    #sign with right path Length
    if pathLen == None:
        cert = cert.add_extension(x509.BasicConstraints(ca= True, path_length= None), critical = True )
    else:
        cert = cert.add_extension(x509.BasicConstraints(ca= True, path_length= pathLen), critical = True )

    cert = cert.sign(caKeyIn, hashAlgo, default_backend())
    return cert

def signTlsCsrWithCaKey(csrIn, issuerCert, caKeyIn, cdpList = list(), aiaList = list(), pathLen = None , hashAlgo = hashes.SHA256()):
    
    hostname = csrIn.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
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
     datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    ).not_valid_after(
     # Our certificate will be valid for 52 weeks
     datetime.datetime.utcnow() + datetime.timedelta(weeks=52)
    ).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True 
    ).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False  )
    
    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)


    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= False, path_length= pathLen), critical = True )

    cert = cert.sign(caKeyIn, hashAlgo, default_backend())

    return cert


def signTlsCsrWithCaKeyNoAddSan(csrIn, issuerCert, caKeyIn, cdpList = list(), aiaList = list(), pathLen = None , hashAlgo = hashes.SHA256()):
    
    hostname = csrIn.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
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
     datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    ).not_valid_after(
     # Our certificate will be valid for 10 days
     datetime.datetime.utcnow() + datetime.timedelta(weeks=52)
    ).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH, x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True )
    
    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)


    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= False, path_length= pathLen), critical = True )

    cert = cert.sign(caKeyIn, hashAlgo, default_backend())


    return cert

def createNewTlsCert(subjectShortName: str, issuerShortName: str, subjectPassphrase = None, issuerPassphrase = None):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( localPath)) / subjectShortName
    if os.path.isdir(thePath):
        print("{} already exists. Delete or rename and try again".formad(thePath))
        sys.exit()
    else:
        os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(2048)
    keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)

    issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( localPath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( localPath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( localPath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( localPath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()


    theTlsCert = signTlsCsrWithCaKey(theCsrWeNeed, issCert, issCaKey, cdps, aias)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theTlsCert)
    with open(thePath / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))
    
    buildChain(theTlsCert, subjectShortName)

    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( localPath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))

def createNewTlsCSR(subjectShortName: str, subjectPassphrase = None):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( localPath)) / subjectShortName
    if os.path.isdir(thePath):
        print("{} already exists. Delete or rename and try again".formad(thePath))
        sys.exit()
    else:
        os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(2048)
    keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)

    subCertFileName = thePath / "cert.csr"
    
    with open(subCertFileName, "wb") as f:
        f.write(theCsrWeNeed.public_bytes(serialization.Encoding.PEM))


    theTlsCert = signTlsCsrWithCaKey(theCsrWeNeed, issCert, issCaKey, cdps, aias)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theTlsCert)
    with open(thePath / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))
    
    buildChain(theTlsCert, subjectShortName)

    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( localPath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))



def createCRL( issuerShortName: str,  issuerPassphrase = None):

    issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
    
    revFile = ((Path( localPath)) / issuerShortName) / "revoked.txt"
    serials = list()
    if os.path.isfile(revFile):
        with open(revFile, "r") as f:
            for ii in f:
                serials.append("0x{}".format(ii)) 
    else:
        print("{} does not exist in your CA folder.  It should be a txt file full of serial numbers".format(revFile))
        print("Creating an empty CRL to publish")

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issCert.subject)
    builder = builder.last_update(datetime.datetime.today() - datetime.timedelta(days =1))

    if issCert.subject == issCert.issuer:
        builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(days =180))
    else:    
        builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(days =90))
    
    for s in serials:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(int( s, 16)).revocation_date(
        datetime.datetime.today()
        ).build()
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(issCaKey, algorithm=hashes.SHA256())


    crlFileName = ((Path( localPath)) / issuerShortName) / "filePEM.crl"


    with open(crlFileName, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    
 
    crlFileName = ((Path( localPath)) / issuerShortName) / "fileDER.crl"
    with open(crlFileName, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.DER))



def createNewTlsCsr(subjectShortName: str, subjectPassphrase = None):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( localPath)) / subjectShortName
    os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(2048)
    keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsrTLS(thisOneKey, subjectShortName)

    fileName = thePath / "file.csr"
    with open(fileName, "wb") as f:
            f.write(theCsrWeNeed.public_bytes(
            encoding=serialization.Encoding.PEM),
            )

    

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

def loadCertsFromFolder(folderName : Path) -> list:
    dBack = list()
    for r, d, f in os.walk(folderName, topdown=False):
        #print(r)
        for file in f:
            fullName = Path(r) / file

            if fullName.suffix.lower() not in [".pem",".crt",".cer"]:
                continue
            
            if fullName.parts[-1] == "key.pem":
                continue
            #do work
            theRes = (readCertFileListBack(fullName)[0])
            if theRes != None:
                dBack.append( theRes)

    return dBack

def parseCertsFromPEMs(pemText : str) -> list:
    """
    this creates a list of x509 objects from text that is PEMs cat'd together
    """
    lines = pemText.split("\n")
    
    realist = list()
    ht = {}
    index = 0
    inCert = False
    for line in lines:
        if line.lower().find("-----beg") > -1:
            inCert = True
            curCert = "-----BEGIN CERTIFICATE-----\n"
            continue

        elif inCert == True and line.lower().find("-----end") < 0:
            curCert += (line + "\n")
            continue

        elif inCert == True and line.lower().find("-----end") > -1:
            curCert += "-----END CERTIFICATE-----\n"
            ht.update({index : curCert})
            index +=1

            theCert = None
            theCert = x509.load_pem_x509_certificate(curCert.encode('utf-8'), default_backend())
            realist.append(theCert)

    return realist

def bIsThisCertInThisList(cert : x509.Certificate, certList : list) -> bool:
    """
    Checks if one cert is in a list of certs and returns a bool
    """
    bIsInList = False
    for oneMem in certList:
        if oneMem.subject.rfc4514_string() == cert.subject.rfc4514_string():
            if oneMem.fingerprint == cert.fingerprint:
                return True
    
    return bIsInList

def diffCertLists(leftList : list, rightList : list) -> dict:
    """
    Return diff between to lists of certs    
    """
    missingFromLeft = list()
    missingFromRight = list()
    for oLeft in leftList:
        if oLeft not in rightList:
            missingFromLeft.append(oLeft)
            continue
        #if bIsThisCertInThisList(oLeft, rightList) == False:
            #in right but not left
            #missingFromLeft.append(oLeft)

    for oRight in rightList:
        if oRight not in leftList:
            missingFromRight.append(oRight)
            continue
        #if bIsThisCertInThisList(oRight, leftList) == False:
            #in left but not in right
            #missingFromRight.append(oRight)
            
    result =  {'MissingFromRight' : missingFromRight , 'MissingFromLeft' : missingFromLeft}
    return result

def appendFile(file : Path, text : str):
    tFile = open(file, "a")
    tFile.write(text)
    tFile.flush()
    tFile.close()

def get_certificates(self):
    from OpenSSL.crypto import  _ffi, _lib, X509
    """
    Returns all certificates for the PKCS7 structure, if present. Only
    objects of type *signed* or *signed and enveloped* can embed
    certificates.
    :return: The certificates in the PKCS7, or ``None`` if
        there are none.
    :rtype: :class:`tuple` of :class:`X509` or ``None``
    """
    
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert

    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        x509 = _ffi.gc(_lib.X509_dup(_lib.sk_X509_value(certs, i)),
                        _lib.X509_free)
        pycert = X509._from_raw_x509_ptr(x509)
        pycerts.append(pycert.to_cryptography())
    if pycerts:
        return tuple(pycerts)

def readP7BFile(file: Path) -> list:
    
    if os.path.isfile(file):

        cFile = open(file, "rb")
        databack = cFile.read()
        cFile.close()
        try:
            bob = OpenSSL.crypto.load_pkcs7_data(FILETYPE_PEM , databack)
            
            certs = get_certificates(bob)
        except Exception as e:
            try:
                bob = OpenSSL.crypto.load_pkcs7_data(FILETYPE_ASN1 , databack)
                certs = get_certificates(bob)
            except Exception as e:
                #probbly not pkcs7
                certs = list()
        return certs
    else:
        print("{} is not a file".format(file))

def readCertFileListBack(file: Path) -> list:
    
    if os.path.isfile(file):
        certs = list()
        cFile = open(file, "rb")
        databack = cFile.read()
        cFile.close()
        try:
            bob = x509.load_pem_x509_certificate(databack, default_backend())
            certs.append(bob)
        except Exception as e:
            try:
                bob = x509.load_der_x509_certificate(databack, default_backend())
                certs.append(bob)
            except Exception as e:
                #probbly not pkcs7
                
                raise
        return certs
    else:
        print("{} is not a file".format(file))

def screen(data : str):
    """
    If verbose, print to screen
    """
    global verbose
    if verbose:
        print(data)

def findParentCertInList(child, certList):
    found = False
    for isThatYouDad in certList:
        if isThatYouDad.subject.rfc4514_string() == child.issuer.rfc4514_string() :
            #possible match must test.
            
            signature_hash_algorithm = child.signature_hash_algorithm
            signature_bytes = child.signature
            signer_public_key = isThatYouDad.public_key()

            if isinstance(signer_public_key, rsa.RSAPublicKey):
                verifier = signer_public_key.verifier(
                    signature_bytes, padding.PKCS1v15(), signature_hash_algorithm
                )
            elif isinstance(signer_public_key, ec.EllipticCurvePublicKey):
                verifier = signer_public_key.verifier(
                    signature_bytes, ec.ECDSA(signature_hash_algorithm)
                )
            else:
                verifier = signer_public_key.verifier(
                    signature_bytes, signature_hash_algorithm
                )

            verifier.update(child.tbs_certificate_bytes)
            try:
                verifier.verify()
                return isThatYouDad
            except:
                #do nothing
                pass
    return found

def bIsRootCA(cert : cryptography.x509.Certificate) -> bool:

    if cert.issuer.rfc4514_string() == cert.subject.rfc4514_string() and bIsCA(cert):
        return True
    else:
        return False

def bIsCA(cert : cryptography.x509.Certificate) -> bool:

    for ext in cert.extensions:
        if ext.oid._name == "basicConstraints":
            return ext.value.ca

def getIssuerFromAIA(certIn : cryptography.x509.Certificate) -> cryptography.x509.Certificate:
    """
    Use the AIA to get a copy of the Issuer cert.  Works with HTTP only, no LDAP now.
    """
    found = False
    for ext in certIn.extensions:
        if ext.oid._name == "authorityInfoAccess" :
            #print(ext.oid._name)
            for aia in ext.value:
                if aia.access_method._name == "caIssuers":
                    URL = aia.access_location.value
                    if URL.startswith("http"):
                        #get this URL
                        try:
                            databack = requests.get(URL, stream=False, timeout=25)
                            theCert = x509.load_der_x509_certificate(databack.content, default_backend())
                            return theCert
                        except Exception as e:
                            print(e)

                        

            pass
    if not found:
        return False

def printCertList(certList : list()):
    for cer in certList:
        print(cer.subject.rfc4514_string())

def createOrderedCertChain(certs : list) -> list:
    """
    Takes in a cert or list of certs. Finds the entity cert to start the chain. Then builds the chain, first from cacerts list, if applicable.
    Then trying AIA, and finally the Mozilla root list as needed.
    returns the chain as a list of certs with the entity first and including the root.

    """
    ordList = list()
    root = None
    entityCert = None
    entCount = 0

    #make sure we have only one leaf cert and make it the start of the chain
    for cer in certs:
        if not bIsCA(cer):
            entityCert = cer
            entCount += 1
            ordList.append(entityCert)
        if cer.issuer.rfc4514_string() == cer.subject.rfc4514_string():
            root = cer
            
    if entCount > 1:
        raise Exception("There is more than one entity certificate in the collection. You must process manually") 

    if entCount == 0:
        raise Exception("There is no entity certificate in the collection. You must process manually. You may have the wrong file") 

    #the found leaf is the child for now
    child = entityCert
    while(True):


        global folderCerts
        parent = findParentCertInList(child, folderCerts)
        if parent == False:
            #todo: incomplete chain need to use AIA to get parent  
            parent = getIssuerFromAIA(child)
            if parent == False:
                global mozRoots
                parent = findParentCertInList(child, mozRoots)
                if parent == False:
                    print("Having trouble building the chain. Here is what we have.\n")
                    printCertList(ordList)
                    print("This cert is :\n  Subject: {} \n  Issuer: {}".format(child.subject.rfc4514_string(),child.issuer.rfc4514_string()))
                    print("\nThis may be due to bad PKI Vendor practices around cross-signing or AIAs\n")
                    print("Find Issuer {} \n and place it in the cacerts folder".format(child.issuer.rfc4514_string()))
            
                    raise Exception("Could not find Issuer {} \nYou will need to figure this out.  =()".format(child.issuer.rfc4514_string()))
                else:
                    print("Had to find a parent for {} at Mozilla".format(child.issuer.rfc4514_string()))
            pass
        if bIsRootCA(parent):
            #not done
            ordList.append(parent)
            return ordList
        else:
            ordList.append(parent)

        child = parent

def certListToCaTopDownPEM(certs : list):
    pemData = ""
    for cert in certs:
        ccc = (cert.public_bytes(encoding=serialization.Encoding.PEM)).decode("utf-8")
        pemData += ccc
    
    return pemData

def getMozillaRoots() -> list:
    """
    Gets the list of current Moz roots from a static URL and converts them to a list of certs
    """
    try:
        url = "https://ccadb-public.secure.force.com/mozilla/IncludedCACertificateReportPEMCSV"
        databack = requests.get(url, stream=False, timeout=25)
        lines = databack.text.split("\n")
        
        realist = list()
        ht = {}
        index = 0
        inCert = False
        for line in lines:
            if line.lower().find("-----beg") > -1:
                inCert = True
                curCert = "-----BEGIN CERTIFICATE-----\n"
                continue

            elif inCert == True and line.lower().find("-----end") < 0:
                curCert += (line + "\n")
                continue

            elif inCert == True and line.lower().find("-----end") > -1:
                curCert += "-----END CERTIFICATE-----\n"
                ht.update({index : curCert})
                index +=1

                theCert = None
                theCert = x509.load_pem_x509_certificate(curCert.encode('utf-8'), default_backend())
                realist.append(theCert)

        return realist
    except requests.exceptions.ConnectionError:
        print("Couldn't {}\n\n".format(url))
        raise

def getCnFromRDN(rdn : cryptography.x509.name.Name) -> str:
    for part in rdn:
        if part.oid._name == "commonName":
            return part.value

    return None
     
def analyzeChainFile(certList : list):
    
    i = 0
    for oCert in certList:
        print("Cert[{}]".format(i))
        print("  Subject: {} \n  Issuer: {}\n".format(oCert.subject.rfc4514_string(),oCert.issuer.rfc4514_string()))
                
        i+=1

def buildChain(certIn, shortName):
    global folderCerts
    folderCerts = loadCertsFromFolder(localPath)
    theList = list()
    theList.append(certIn)
    orderedCerts = createOrderedCertChain(theList)

    del orderedCerts[0]
    strOfPEMs = certListToCaTopDownPEM(orderedCerts)

    outFile = (localPath / shortName) / "chain.pem"
            
    if os.path.isfile(outFile):
        os.remove(outFile)
    wFile = open(outFile, "w")
    wFile.write(strOfPEMs)
    wFile.close()

def signCsrNoQuestionsTlsServer(csrFile:Path(), issuerShortName: str, subjectPassphrase = None, issuerPassphrase = None  ):
    #load the csr
    csr = None
    if os.path.isfile(csrFile):
        fh = open(csrFile, "rb" )
        fData = fh.read()
        fh.close()
        try:
            csr = x509.load_pem_x509_csr(fData, default_backend())
            
        except:
            try:
                csr = x509.load_der_x509_csr(fData, default_backend())
                
            except:
                raise

        #should have a csr here
        #make it into a cert object for signing
        if subjectPassphrase != None:
            subjectPassphrase = (subjectPassphrase)

        subjectShortName = getCnFromRDN(csr.subject)
        #create the folder for the sub
        thePath = (Path( localPath)) / subjectShortName
        if os.path.isdir(thePath):
            pass
        else:
            os.mkdir(thePath)

        #create key and key file. NOt needed for CSR only
        #thisOneKey = newRSAKeyPair(2048)
        #keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
                
        #we have key and folder create CSR and sign
        #theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)
        theCsrWeNeed = csr
        issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
        issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
        subCertFileName = thePath / "cert.pem"

        theTlsCert = signTlsCsrWithCaKeyNoAddSan(theCsrWeNeed, issCert, issCaKey)
        # Write our certificate out to disk.
        with open(subCertFileName, "wb") as f:
            f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

        #also do a fun named cer verions
        fileName = getFileNameFromCert(theTlsCert)
        with open(thePath / fileName, "wb") as f:
            f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))
        
        buildChain(theTlsCert, subjectShortName)


def signCsrNoQuestionsCA(csrFile:Path(), issuerShortName: str, subjectPassphrase = None, issuerPassphrase = None  ):
    #load the csr
    csr = None
    if os.path.isfile(csrFile):
        fh = open(csrFile, "rb" )
        fData = fh.read()
        fh.close()
        try:
            csr = x509.load_pem_x509_csr(fData, default_backend())
            
        except:
            try:
                csr = x509.load_der_x509_csr(fData, default_backend())
                
            except:
                raise

        #should have a csr here
        #make it into a cert object for signing
        if subjectPassphrase != None:
            subjectPassphrase = (subjectPassphrase)

        subjectShortName = getCnFromRDN(csr.subject)
        #create the folder for the sub
        thePath = (Path( localPath)) / subjectShortName
        if os.path.isdir(thePath):
            pass
        else:
            os.mkdir(thePath)

        #create key and key file. NOt needed for CSR only
        #thisOneKey = newRSAKeyPair(2048)
        #keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
                
        #we have key and folder create CSR and sign
        #theCsrWeNeed = createNewCsr(thisOneKey, subjectShortName)
        theCsrWeNeed = csr
        issCert = readCertFile(((Path( localPath)) / issuerShortName) / "cert.pem")
        issCaKey = readPemPrivateKeyFromFile(((Path( localPath)) / issuerShortName) / "key.pem", issuerPassphrase)
        subCertFileName = thePath / "cert.pem"

        theCaCertBack = signSubCaCsrWithCaKey(theCsrWeNeed, issCert, issCaKey)
        #theCaCertBack =  signTlsCsrWithCaKeyNoAddSan(theCsrWeNeed, issCert, issCaKey)
        # Write our certificate out to disk.
        with open(subCertFileName, "wb") as f:
            f.write(theCaCertBack.public_bytes(serialization.Encoding.PEM))

        #also do a fun named cer verions
        fileName = getFileNameFromCert(theCaCertBack)
        with open(thePath / fileName, "wb") as f:
            f.write(theCaCertBack.public_bytes(serialization.Encoding.PEM))
        
        buildChain(theCaCertBack, subjectShortName)


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
    
    if currentMode == None:
        print("Your -m or --mode must be set")
        print(syntax)
        sys.exit()

    if currentMode == Mode.NewRootCA:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            createNewRootCA(subjectCN)
            sys.exit()
        
    if currentMode ==  Mode.NewSubCA:
        if subjectCN == "blank" or signerCN == "blank":  
            print("Your -n or --name must be set and -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            createNewSubCA(subjectCN, signerCN, None, None )
            sys.exit()

    if currentMode == Mode.NewLeafTLS:
        if subjectCN == "blank" or signerCN == "blank":  
            print("Your -n or --name must be set and -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            createNewTlsCert(subjectCN, signerCN)
            sys.exit()

    if currentMode == Mode.NewTlsFromCSR:
        if  signerCN == "blank":  
            print("Your -s or --signer must be set")  
            print(syntax)
            sys.exit()

        #check if CSR file is there
        if not os.path.isfile(Path(csrFile)):
            print("The file {} does not seem to exist".format(csrFile))
            print(syntax)
            sys.exit()
        
        if  signerCN == "blank":  
            print("Your -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            #read the csr and do the needuful
            signCsrNoQuestionsTlsServer(Path(csrFile) , signerCN)   
            sys.exit()
            

    if currentMode == Mode.SignCRL:
        if  signerCN == "blank":  
            print("Your -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            createCRL(signerCN)
            sys.exit()

    if currentMode == Mode.NewSubCaFromCSR:
        if  signerCN == "blank":  
            print("Your -s or --signer must be set")  
            print(syntax)
            sys.exit()

        if not os.path.isfile(Path(csrFile)):
            print("The file {} does not seem to exist".format(csrFile))
            print(syntax)
            sys.exit()
        else:
            #sign it!
            signCsrNoQuestionsCA(Path(csrFile), signerCN)
            pass            
            
    if currentMode == Mode.CreateCaCSR:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()

    if currentMode == Mode.CreateTlsCsr:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            createNewTlsCsr(subjectCN)
            sys.exit()
            
    
    print("Not sure how we got here. I hope you can read and write Python")
    sys.exit()
 


if __name__ == "__main__":
    main(sys.argv[1:])
 