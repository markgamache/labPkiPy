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
from cryptography.hazmat.primitives.hashes import HashAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.x509.oid import ExtensionOID
from enum import Enum
import json
from mock import Mock



syntax = """
This tool is for PKI testing and training. It does scary things. BEWARE
    --name is the CN used in the certificate being created
    --signer must be the CN of the issuer you are using. 
    -m or --mode for mode. must be one of:
        NewRootCA
        NewSubCA
        NewSubCaFromCSR
        NewTlsFromCSR
        SignCRL
        CreateTlsCsr
        CreateCaCSR
        NewLeafClient
        NewSubCaClientAuth
        NewLeafTLS

    --hash it the hashing algo use when signing the cert. SHA1, MD5, SHA512, or SHA256 (def)
    -h or --help for help
    -c or --csr for the path to a CSR file for signing
    -v or --verbose for verbose. Sorry not very verbose now"
    --validfrom cert start, see dates below
    --validto cert epxpiry date, see dates below
    --keysize Just the int 
        RSA key size, 1024, 2048, 4096 
        ECC key size 256, 384, 521
    --isca true or false. This sets the Basic Constraint (empty chooses the proper value) This is for testing broken things
    --pathlength the path length the Basic Constraints (def is None) use any int. Must be a CA in --isca to have a length 
    --noeku this flag means despite being a client or server cert, leave off the EKUs. Used for testing bad TLS stacks
    --ekus list of EKUs to include. Comma seperated. Any combination of:
        SERVER_AUTH
        CLIENT_AUTH
        CODE_SIGNING
        EMAIL_PROTECTION 
        TIME_STAMPING 
        OCSP_SIGNING 
        ANY_EXTENDED_KEY_USAGE

    --noku this is the default. Some stacks may do fun things based on use case an KU
    --kus list of Key Usage items. Comma seperated. Any combinaiton of:
        digital_signature
        content_commitment
        key_encipherment
        data_encipherment
        key_agreement
        key_cert_sign
        crl_sign
        encipher_only
        decipher_only

    --basepath  dir path where the issuer resides and the new cert folder will be created
    --nosans  this flag leaves out SANs, so only the CN is present for naming. This is for testing bad TLS stacks
    --sans Comma seperated. list of DNS names for SANs.  No support as of now, for other types 
    --ncallowed  string of DNS names, comma seperated, to be added to the names allowed name constraint 
    --ncdisallowed string of DNS names, comma seperated, to be added to the names disallowed name constraint
    --cps  The URL you want the CPS to point to

    Date Time options: janOf2018, marchOf2018, janOf2028, janOf2048, dtMinusTenMin, dtMinusOneHour, dtMinusTwoYears, dtPlusTenMin, dtPlusOneYear, dtPlusFiveYears, 
                       dtPlusTenYears, dtPlusTwentyYears, now


"""


class Mode(Enum):
    NewRootCA = 1
    NewSubCA = 2
    NewLeafTLS = 3
    NewSubCaFromCSR = 4
    NewTlsFromCSR = 5
    SignCRL = 6
    CreateCaCSR = 7
    CreateTlsCsr = 8
    NewLeafClient = 9
    NewSubCaClientAuth = 10

class CommonDateTimes(Enum):
    janOf2018 = datetime.datetime(2018, 1,2)
    marchOf2018 = datetime.datetime(2018, 3,2)
    janOf2028 = datetime.datetime(2028, 1,2)
    janOf2048 = datetime.datetime(2048, 1,2)
    dtMinusTenMin = datetime.datetime.utcnow() - datetime.timedelta(seconds=600)
    dtMinusOneHour = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
    dtMinusTwoYears = datetime.datetime.utcnow() - datetime.timedelta(weeks=104)
    dtPlusTenMin = datetime.datetime.utcnow() + datetime.timedelta(seconds=600)
    dtPlusOneYear = datetime.datetime.utcnow() + datetime.timedelta(weeks=52)
    dtPlusFiveYears = datetime.datetime.utcnow() + datetime.timedelta(weeks=260)
    dtPlusTenYears = datetime.datetime.utcnow() + datetime.timedelta(weeks=520)
    dtPlusTwentyYears = datetime.datetime.utcnow() + datetime.timedelta(weeks=1040)
    now = datetime=datetime.datetime.utcnow()

class CommonTimeSpans(Enum):
    tsOneYear = datetime.timedelta(weeks=52)
    tsTenMin = datetime.timedelta(minutes=10)
    tsOneHour = datetime.timedelta(minutes=60)

class x509Out(dict):
    def __init__(self, basePath, serial, subject, derfile):
        dict.__init__(self, basePath=basePath, serial=serial, subject=subject, DERFile=derfile)

def newRSAKeyPair(size: int = 2048):
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=size,
    backend=default_backend()
    )
    return key

def newECCKeyPair(size: int = 256):

    curve = ec.SECP256K1()  
    
    if size == 384:
        curve = ec.SECP384R1()

    if size == 521:
        curve = ec.SECP521R1()

    key = ec.generate_private_key(curve, backend=default_backend())
    
    return key

def keyToPemFile(keyIn, fileName, passphrase):

    if os.path.isfile(fileName):
        keyB = readPemPrivateKeyFromFile(fileName, passphrase)    
        return keyB

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

    return keyIn

def readPemPrivateKeyFromFile(fileIn, passphrase = None):
    if os.path.isfile:
        f = open(fileIn, "rb")
        public_pem_data = f.read()
        f.close()

        key = cryptography.hazmat.primitives.serialization.load_pem_private_key(public_pem_data, passphrase ,  backend=default_backend())

        return key
    else:
        raise( "that ain't no file")

def createNewRootCaCert(cnIn: str, 
                        keyIn, 
                        certFileName: Path,
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                        validTo: datetime = CommonDateTimes.dtPlusTwentyYears.value,
                        pathLen = None,
                        hashAlgo = hashes.SHA256(),
                        isAcA: bool = True,
                        allowedNames: list = None,
                        disallowedNames: list = None,
                        KUs: list = None,
                        EKUs: list = None,
                        cpsURL: str = None
                        ) -> x509.Certificate:

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
     validFrom
    ).not_valid_after(
     validTo
    ).add_extension(x509.BasicConstraints(ca= isAcA, path_length= pathLen), critical = True)

    cspP = createCPSPols(cert, cpsURL)
    pcS = x509.PolicyConstraints(1, None)
    thePols = x509.CertificatePolicies(cspP)
    cert = cert.add_extension(thePols, False)
    

    ncListAllow = list()   
    ncListDisAllow = list()    

    if type( allowedNames) == list: 
        if len(allowedNames) == 0:
            allowedNames = None

    if type( disallowedNames) == list: 
        if len(disallowedNames) == 0:
            disallowedNames = None

    if allowedNames == None:
        ncListAllow = None
    elif len(allowedNames) > 0:
        for nm in allowedNames:
            ncListAllow.append(x509.DNSName(nm))
        
    if disallowedNames == None:
        ncListDisAllow = None
    elif len(disallowedNames) > 0:
        for nm in disallowedNames:
            ncListDisAllow.append(x509.DNSName(nm))
    
    if ncListDisAllow == None and ncListAllow == None:
        pass
    else:
        cert = cert.add_extension( x509.NameConstraints(ncListAllow, ncListDisAllow), critical = True)

    #if KUs are present add the ext in accordance
    if len(KUs) > 0:
        dSig = False 
        conCom = False
        keyEnc = False
        datEnci = False
        keyAgr = False
        keyCeSi = False
        crlSig = False
        encOnly = False
        decOnly = False

        for ku in KUs:
            if ku == "digital_signature":
                dSig = True

            if ku == "content_commitment":
                conCom = True

            if ku == "key_encipherment":
                keyEnc = True

            if ku == "data_encipherment":
                datEnci = True

            if ku == "key_agreement":
                keyAgr = True

            if ku == "key_cert_sign":
                keyCeSi = True
    
            if ku == "crl_sign":
                crlSig = True

            if ku == "encipher_only":
                encOnly = True

            if ku == "decipher_only":
                decOnly = True
            
        cert = cert.add_extension(x509.KeyUsage(digital_signature=dSig, 
                                                content_commitment=conCom, 
                                                key_encipherment=keyEnc, 
                                                data_encipherment=datEnci, 
                                                key_agreement=keyAgr, 
                                                key_cert_sign=keyCeSi, 
                                                crl_sign=crlSig, 
                                                encipher_only=encOnly, 
                                                decipher_only=decOnly
                                                ), critical =True)

    #if EKUs are present, add them
    if len(EKUs) > 0:
        realEKUList = list()

        for eku in EKUs:
            if eku == "SERVER_AUTH":
                realEKUList.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)

            if eku == "CLIENT_AUTH":
                realEKUList.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku == "CODE_SIGNING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku == "EMAIL_PROTECTION":
                realEKUList.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)

            if eku == "TIME_STAMPING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku == "OCSP_SIGNING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku == "ANY_EXTENDED_KEY_USAGE":
                realEKUList.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)


        cert = cert.add_extension(x509.ExtendedKeyUsage(realEKUList), critical=True )


    cert =  cert.sign(keyIn, hashAlgo, default_backend())
    # Write our certificate out to disk.
    with open(certFileName, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(cert)
    with open(certFileName.parent / fileName, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))

    return cert

def createNewRootCA(shortName: str, 
                    basePath: Path, 
                    passphrase = None,
                    keysize = 4096,
                    validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                    validTo: datetime = CommonDateTimes.dtPlusTwentyYears.value,
                    pathLen = None,
                    hashAlgo = hashes.SHA256(),
                    isAcA: bool = True,
                    allowedNames: list = None,
                    disallowedNames: list = None,
                    KUs: list = None,
                    EKUs: list = None,
                    cpsURL: str = None
                    ):
    
    if passphrase != None:
        passphrase = (passphrase)

    #create the folder
    thePath = (Path( basePath)) / shortName
    try:
        os.mkdir(thePath)
    except:
        pass

    #create key and key file
    if keysize in [1024, 2048, 4096]:
        thisOneKey = newRSAKeyPair(keysize)
    else:
        thisOneKey = newECCKeyPair(keysize)

    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", passphrase)

    theRoot = createNewRootCaCert(shortName, thisOneKey, thePath / "cert.pem", validFrom, validTo, pathLen , hashAlgo, isAcA, allowedNames, disallowedNames, KUs,  EKUs, cpsURL)

    derFilename = getFileNameFromCert(theRoot)    

    certOut = x509Out(str( thePath), hex( theRoot.serial_number)[2:], str( theRoot.subject), str(thePath / derFilename))
    jOut = json.dumps(certOut)
    return jOut

def createNewSubCA(subjectShortName: str, 
                    issuerShortName: str, 
                    basePath: Path,
                    subjectPassphrase = None, 
                    issuerPassphrase = None,
                    keysize = 4096,
                    validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                    validTo: datetime = CommonDateTimes.dtPlusTwentyYears.value,
                    pathLen = None,
                    hashAlgo = hashes.SHA256(),
                    isAcA: bool = True,
                    allowedNames: list = None,
                    disallowedNames: list = None,
                    KUs: list = None,
                    EKUs: list = None,
                    cpsURL: str = None
                    ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    if os.path.isdir(thePath):
        pass
    else:
        os.mkdir(thePath)

    #create key and key file
    if keysize in [1024, 2048, 4096]:
        thisOneKey = newRSAKeyPair(keysize)
    else:
        thisOneKey = newECCKeyPair(keysize)

    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign. CSR only, signed to RAM, not disk
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName, hashAlgo)

    issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            theURI = x509.UniformResourceIdentifier( m.strip())
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), theURI))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()

    theSubCACert = signSubCaCsrWithCaKey(theCsrWeNeed, 
                                        issCert,  
                                        issCaKey , 
                                        cdps, 
                                        aias , 
                                        validFrom,
                                        validTo,
                                        pathLen,
                                        hashAlgo,
                                        isAcA,
                                        allowedNames,
                                        disallowedNames,
                                        KUs,
                                        EKUs,
                                        cpsURL)


    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theSubCACert)
    with open(thePath / fileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.DER))

    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( basePath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.DER))

    derFilename = getFileNameFromCert(theSubCACert)    
    certOut = x509Out(str( thePath), hex( theSubCACert.serial_number)[2:], str( theSubCACert.subject), str(thePath / derFilename))
    jOut = json.dumps(certOut)
    return jOut

#does not currently support NCs for this
def createNewSubCAClientAuth(subjectShortName: str, 
                    issuerShortName: str, 
                    basePath: Path,
                    subjectPassphrase = None, 
                    issuerPassphrase = None,
                    keysize = 4096,
                    validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                    validTo: datetime = CommonDateTimes.dtPlusTwentyYears.value,
                    pathLen = None,
                    hashAlgo = hashes.SHA256(),
                    isAcA: bool = True,
                    allowedNames: list = None,  #currently unused 
                    disallowedNames: list = None,  #currently unused 
                    KUs: list = list(), #currently unused 
                    EKUs: list = list() #currently unused 
                    ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    if os.path.isdir(thePath):
        print("{} already exists. Change the name or remove it and try again".format(thePath))
        sys.exit()
    else:
        os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(keysize)
    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign. CSR only, signed to RAM, not disk
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName, hashAlgo)

    issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()

    theSubCACert = signSubCaCsrWithCaKeyClientAuth(theCsrWeNeed, 
                                        issCert,  
                                        issCaKey , 
                                        cdps, 
                                        aias , 
                                        validFrom,
                                        validTo,
                                        pathLen,
                                        hashAlgo,
                                        isAcA,
                                        KUs,
                                        EKUs)

    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theSubCACert)
    with open(thePath / fileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.DER))

    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( basePath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theSubCACert.public_bytes(serialization.Encoding.DER))

    derFilename = getFileNameFromCert(theSubCACert)

    certOut = x509Out(str( thePath), hex( theSubCACert.serial_number)[2:], str( theSubCACert.subject), str(thePath / derFilename))
    jOut = json.dumps(certOut)
    return jOut


def createNewCsrSubjectAndSignOnly(privKeyIn, 
                                    cnIn, 
                                    hashAlgo = hashes.SHA256()):
    thisCsr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
     x509.NameAttribute(NameOID.COMMON_NAME, cnIn), ])).sign(privKeyIn, hashAlgo, default_backend())

    return thisCsr

def createNewCsrObjTLS(privKeyIn, 
                        cnIn,
                        hashAlgo = hashes.SHA256(),
                        theSans: list = None
                        ):
    thisCsr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
     # Provide various details about who we are.
     x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
     x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
     x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
     x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
     x509.NameAttribute(NameOID.COMMON_NAME, cnIn), ]))

    if len(theSans) > 0:
        thisCsr = thisCsr.add_extension(x509.SubjectAlternativeName(theSans), critical=False)

    thisCsr = thisCsr.sign(privKeyIn, hashAlgo, default_backend())
    return thisCsr


def getFileNameFromCert(certIn : cryptography.x509):
    
    cnPart = certIn.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    cnPart = cnPart.replace(" " , "")
    serPart = str(hex(certIn.serial_number))
    cnPart = "{}_{}.cer".format(cnPart, serPart[-5:]) 
    
    return cnPart
 

def signSubCaCsrWithCaKeyClientAuth(csrIn: x509.CertificateSigningRequest, 
                        issuerCert: x509.Certificate, 
                        caKeyIn, 
                        cdpList = list(), 
                        aiaList = list(), 
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                        validTo: datetime = CommonDateTimes.dtPlusTenYears.value,
                        pathLen = None ,
                        hashAlgo = hashes.SHA256(),
                        isAcA: bool = True,
                        KUs: list = list(), #currently unused 
                        EKUs: list = list() #currently unused 
                        ) -> x509.Certificate:
    
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
     validFrom
    ).not_valid_after(
     validTo
    )

    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)

    cert = cert.add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False )     

    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= isAcA, path_length= pathLen), critical = True )
    cert = cert.sign(caKeyIn, hashAlgo, default_backend())
    return cert



def signSubCaCsrWithCaKey(csrIn: x509.CertificateSigningRequest, 
                        issuerCert: x509.Certificate, 
                        caKeyIn, 
                        cdpList = list(), 
                        aiaList = list(), 
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                        validTo: datetime = CommonDateTimes.dtPlusTenYears.value,
                        pathLen = None ,
                        hashAlgo = hashes.SHA256(),
                        isAcA: bool = True,
                        allowedNames: list = None,
                        disallowedNames: list = None,
                        KUs: list = None,
                        EKUs: list = None,
                        cpsURL: str = None
                        ):
    
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
     validFrom
    ).not_valid_after(
     validTo
    )

    #if need be strip the date.value upstream.

    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)
    

    cspP = createCPSPols(cert, cpsURL)
    pcS = x509.PolicyConstraints(1, None)
    thePols = x509.CertificatePolicies(cspP)
    cert = cert.add_extension(thePols, False) 
   
    ncListAllow = list()   
    ncListDisAllow = list()    

    if type( allowedNames) == list: 
        if len(allowedNames) == 0:
            allowedNames = None

    if type( disallowedNames) == list: 
        if len(disallowedNames) == 0:
            disallowedNames = None

    if allowedNames == None:
        ncListAllow = None
    elif len(allowedNames) > 0:
        for nm in allowedNames:
            ncListAllow.append(x509.DNSName(nm))
        
    if disallowedNames == None:
        ncListDisAllow = None
    elif len(disallowedNames) > 0:
        for nm in disallowedNames:
            ncListDisAllow.append(x509.DNSName(nm))
    
    if ncListDisAllow == None and ncListAllow == None:
        pass
    else:
        cert = cert.add_extension( x509.NameConstraints(ncListAllow, ncListDisAllow), critical = True)


    #if KUs are present add the ext in accordance
    if len(KUs) > 0:
        dSig = False 
        conCom = False
        keyEnc = False
        datEnci = False
        keyAgr = False
        keyCeSi = False
        crlSig = False
        encOnly = False
        decOnly = False

        for ku in KUs:
            if ku == "digital_signature":
                dSig = True

            if ku == "content_commitment":
                conCom = True

            if ku == "key_encipherment":
                keyEnc = True

            if ku == "data_encipherment":
                datEnci = True

            if ku == "key_agreement":
                keyAgr = True

            if ku == "key_cert_sign":
                keyCeSi = True
    
            if ku == "crl_sign":
                crlSig = True

            if ku == "encipher_only":
                encOnly = True

            if ku == "decipher_only":
                decOnly = True
            
        cert = cert.add_extension(x509.KeyUsage(digital_signature=dSig, 
                                                content_commitment=conCom, 
                                                key_encipherment=keyEnc, 
                                                data_encipherment=datEnci, 
                                                key_agreement=keyAgr, 
                                                key_cert_sign=keyCeSi, 
                                                crl_sign=crlSig, 
                                                encipher_only=encOnly, 
                                                decipher_only=decOnly
                                                ), critical =True)

    #if EKUs are present, add them
    if len(EKUs) > 0:
        realEKUList = list()

        for eku in EKUs:
            if eku == "SERVER_AUTH":
                realEKUList.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)

            if eku == "CLIENT_AUTH":
                realEKUList.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku == "CODE_SIGNING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku == "EMAIL_PROTECTION":
                realEKUList.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)

            if eku == "TIME_STAMPING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku == "OCSP_SIGNING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku == "ANY_EXTENDED_KEY_USAGE":
                realEKUList.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)


        cert = cert.add_extension(x509.ExtendedKeyUsage(realEKUList), critical=True )


    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= isAcA, path_length= pathLen), critical = True )
    cert = cert.sign(caKeyIn, hashAlgo, default_backend())
    return cert


def signTlsNoEKUsCsrWithCaKey(csrIn, 
                        issuerCert, 
                        caKeyIn, 
                        cdpList = list(), 
                        aiaList = list(), 
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin , 
                        validTo: datetime = CommonDateTimes.dtPlusOneYear,
                        hashAlgo = hashes.SHA256()
                        ):
    
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
     validFrom.value
    ).not_valid_after(
     # Our certificate will be valid for 52 weeks
     validTo.value
    ).add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False  )
    
    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)


    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= False, path_length= None), critical = True )

    cert = cert.sign(caKeyIn, hashAlgo, default_backend())

    return cert

def signTlsCsrWithCaKey(csrIn, 
                        issuerCert, 
                        caKeyIn, 
                        cdpList = list(), 
                        aiaList = list(), 
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                        validTo: datetime = CommonDateTimes.dtPlusOneYear.value,
                        hashAlgo = hashes.SHA256(),
                        noSANs: bool = True,
                        isAcA: bool = False,
                        noEkus: bool = False,
                        KUs: list = None,
                        EKUs: list = None,
                        cpsURL: str = None,
                        theSans: list = None
                        ) -> x509.Certificate:
    
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
     validFrom
    ).not_valid_after(
     # Our certificate will be valid for 52 weeks
     validTo
    )


    if noSANs == False:
        cert = cert.add_extension(x509.SubjectAlternativeName(theSans), critical=False  )
    
    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)

    cspP = createCPSPols(cert, cpsURL)
    pcS = x509.PolicyConstraints(1, None)
    thePols = x509.CertificatePolicies(cspP)
    cert = cert.add_extension(thePols, False)
    
    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= isAcA, path_length= None), critical = True )

    #if KUs are present add the ext in accordance
    if len(KUs) > 0:
        dSig = False 
        conCom = False
        keyEnc = False
        datEnci = False
        keyAgr = False
        keyCeSi = False
        crlSig = False
        encOnly = False
        decOnly = False

        for ku in KUs:
            if ku == "digital_signature":
                dSig = True

            if ku == "content_commitment":
                conCom = True

            if ku == "key_encipherment":
                keyEnc = True

            if ku == "data_encipherment":
                datEnci = True

            if ku == "key_agreement":
                keyAgr = True

            if ku == "key_cert_sign":
                keyCeSi = True
    
            if ku == "crl_sign":
                crlSig = True

            if ku == "encipher_only":
                encOnly = True

            if ku == "decipher_only":
                decOnly = True
            
        cert = cert.add_extension(x509.KeyUsage(digital_signature=dSig, 
                                                content_commitment=conCom, 
                                                key_encipherment=keyEnc, 
                                                data_encipherment=datEnci, 
                                                key_agreement=keyAgr, 
                                                key_cert_sign=keyCeSi, 
                                                crl_sign=crlSig, 
                                                encipher_only=encOnly, 
                                                decipher_only=decOnly
                                                ), critical =True)

    #if EKUs are present, add them
    if len(EKUs) > 0:
        realEKUList = list()

        for eku in EKUs:
            if eku == "SERVER_AUTH":
                realEKUList.append(x509.ExtendedKeyUsageOID.SERVER_AUTH)

            if eku == "CLIENT_AUTH":
                realEKUList.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku == "CODE_SIGNING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku == "EMAIL_PROTECTION":
                realEKUList.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)

            if eku == "TIME_STAMPING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CLIENT_AUTH)

            if eku == "OCSP_SIGNING":
                realEKUList.append(x509.ExtendedKeyUsageOID.CODE_SIGNING)

            if eku == "ANY_EXTENDED_KEY_USAGE":
                realEKUList.append(x509.ExtendedKeyUsageOID.EMAIL_PROTECTION)


        cert = cert.add_extension(x509.ExtendedKeyUsage(realEKUList), critical=True )

    cert = cert.sign(caKeyIn, hashAlgo, default_backend())

    return cert

def signClientCsrWithCaKey(csrIn, 
                        issuerCert, 
                        caKeyIn, 
                        cdpList = list(), 
                        aiaList = list(), 
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                        validTo: datetime = CommonDateTimes.dtPlusOneYear.value,
                        hashAlgo = hashes.SHA256(),
                        addSANs: bool = True,
                        KUs: list = list(), #currently not used
                        EKUs: list = list() #currently not used
                        ) -> x509.Certificate:
    
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
     validFrom
    ).not_valid_after(
     # Our certificate will be valid for 52 weeks
     validTo
    ).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True)

    if addSANs:
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False  )
    
    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)

    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= False, path_length= None), critical = True )
    cert = cert.sign(caKeyIn, hashAlgo, default_backend())

    return cert


def signTlsCsrWithCaKeyWithSans(csrIn: x509.CertificateSigningRequest, 
                                issuerCert: x509.Certificate, 
                                caKeyIn, 
                                cdpList = list(), 
                                aiaList = list(), 
                                pathLen = None , 
                                validFrom: datetime = CommonDateTimes.dtMinusTenMin , 
                                validTo: datetime = CommonDateTimes.dtPlusOneYear,
                                hashAlgo = hashes.SHA256(),
                                addSANs: bool = True,
                                isAcA: bool = False
                                ):
    
    hostname = csrIn.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    csrSubject = csrIn.subject
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
     validFrom.value
    ).not_valid_after(
     # Our certificate will be valid for 10 days
     validTo.value
    ).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=True )


    csrSans = None
    try:
        csrSans = csrIn.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except:
        pass

    if csrSans == None:
        cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False  )
    else:
        cert = cert.add_extension(csrSans.value, csrSans.critical  )
    #
    
    #base cert ready

    #add CRPs and AIAs as needed
    if len( aiaList) > 0:
        cert = cert.add_extension(x509.AuthorityInformationAccess(aiaList), critical = False)

    if len( cdpList) > 0:
        cert = cert.add_extension(x509.CRLDistributionPoints(cdpList), critical = False)

    #sign with right path Length
    cert = cert.add_extension(x509.BasicConstraints(ca= isAcA, path_length= pathLen), critical = True )
    cert = cert.sign(caKeyIn, hashAlgo, default_backend())

    return cert

def createNewTlsCert(subjectShortName: str, 
                    issuerShortName: str,
                    basePath: Path, 
                    subjectPassphrase = None, 
                    issuerPassphrase = None,
                    keysize = 2048,
                    validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                    validTo: datetime = CommonDateTimes.dtPlusOneYear.value,
                    hashAlgo = hashes.SHA256(),
                    noSANs: bool = True,
                    isAcA: bool = False,
                    noEkus: bool = False,
                    KUs: list = None,
                    EKUs: list = None,
                    cpsURL: str = None,
                    theSans: list = None
                    ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    if os.path.isdir(thePath):
        print("{} already exists. Delete or rename and try again".format(thePath))
        sys.exit()
    else:
        os.mkdir(thePath)

    #create key and key file
    if keysize in [1024, 2048, 4096]:
        thisOneKey = newRSAKeyPair(keysize)
    else:
        thisOneKey = newECCKeyPair(keysize)

    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName, hashAlgo)

    issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()

    theTlsCert = signTlsCsrWithCaKey(theCsrWeNeed, issCert, issCaKey, cdps, aias, validFrom, validTo, hashAlgo, noSANs, isAcA, noEkus, KUs, EKUs, cpsURL, theSans)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theTlsCert)
    with open(thePath / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))
    
    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( basePath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))
    
    buildChain(theTlsCert, subjectShortName, basePath)

    derFilename = getFileNameFromCert(theTlsCert)    

    certOut = x509Out(str( thePath), hex( theTlsCert.serial_number)[2:], str( theTlsCert.subject), str(thePath / derFilename))
    jOut = json.dumps(certOut)
    return jOut

def createNewTlsCertNoEKUs(subjectShortName: str, 
                    issuerShortName: str,
                    basePath: Path, 
                    subjectPassphrase = None, 
                    issuerPassphrase = None,
                    keysize = 2048,
                    validFrom: datetime = CommonDateTimes.dtMinusTenMin , 
                    validTo: datetime = CommonDateTimes.dtPlusOneYear,
                    hashAlgo = hashes.SHA256()
                    ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    if os.path.isdir(thePath):
        print("{} already exists. Delete or rename and try again".format(thePath))
        sys.exit()
    else:
        os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(keysize)
    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName, hashAlgo)

    issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()

    
    theTlsCert = signTlsNoEKUsCsrWithCaKey(theCsrWeNeed, issCert, issCaKey, cdps, aias, validFrom, validTo, hashAlgo)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theTlsCert)
    with open(thePath / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))
    
    
    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( localPath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))
    
    buildChain(theTlsCert, subjectShortName)



def createNewClientCert(subjectShortName: str, 
                    issuerShortName: str,
                    basePath: Path, 
                    subjectPassphrase = None, 
                    issuerPassphrase = None,
                    pathLen = None,
                    keysize = 2048,
                    validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                    validTo: datetime = CommonDateTimes.dtPlusOneYear.value,
                    hashAlgo: HashAlgorithm = hashes.SHA256(),
                    addSANs: bool = True,
                    isAcA: bool = True,
                    KUs: list = list(), 
                    EKUs: list = list()
                    ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    if os.path.isdir(thePath):
        pass
    else:
        os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(keysize)
    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName, hashAlgo)

    issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
    subCertFileName = thePath / "cert.pem"

    #look for AIA and CDP files in the issuer folder
    aias = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
        for m in f:
            aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
        f.close()
       
    cdps = list()
    if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
        f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
        for m in f:
            cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
        f.close()

    theTlsCert = signClientCsrWithCaKey(theCsrWeNeed, issCert, issCaKey, cdps, aias, validFrom, validTo, hashAlgo, addSANs, KUs, EKUs)
    # Write our certificate out to disk.
    with open(subCertFileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

    #also do a fun named cer verions
    fileName = getFileNameFromCert(theTlsCert)
    with open(thePath / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))
    
    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( basePath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))
    
    buildChain(theTlsCert, subjectShortName, basePath)

    derFilename = getFileNameFromCert(theTlsCert)    
    certOut = x509Out(str( thePath), hex( theTlsCert.serial_number)[2:], str( theTlsCert.subject), str(thePath / derFilename))
    jOut = json.dumps(certOut)
    return jOut


def createNewTlsCSR(subjectShortName: str, subjectPassphrase = None, keysize: int = 2048):
    
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
    thisOneKey = newRSAKeyPair(keysize)
    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName)

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


    #as needed add the issuer issued folder and add the cert to that folder
    issued = ((Path( localPath)) / issuerShortName) / "issued"
    if os.path.isdir(issued):
        pass
    else:
        os.mkdir(issued)
    
    with open(issued / fileName, "wb") as f:
        f.write(theTlsCert.public_bytes(serialization.Encoding.DER))

        
    buildChain(theTlsCert, subjectShortName)



def createCRL( issuerShortName: str,  
                basePath: Path,
                issuerPassphrase = None,
                validFrom: datetime = CommonDateTimes.dtMinusTenMin.value , 
                validTo: datetime = CommonDateTimes.dtPlusOneYear.value ,
                hashAlgo = hashes.SHA256()               
                ):

    issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
    issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
    
    #this code is weak. It uses a list of serials that may not exist and makes the rovke data now.  Good code would make sure
    # that the cert even existed and was time valid, to avoid CRL bloat

    revFile = ((Path( basePath)) / issuerShortName) / "revoked.txt"
    serials = list()
    if os.path.isfile(revFile):
        with open(revFile, "r") as f:
            for ii in f:
                #they came in as hex assumed. Most UIs show them hex and not big int
                serials.append("0x{}".format(ii)) 
    else:
        #print("{} does not exist in your CA folder.  It should be a txt file full of serial numbers".format(revFile))
        #print("Creating an empty CRL to publish")
        pass

    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issCert.subject)
    builder = builder.last_update(validFrom)
    builder = builder.next_update(validTo)
    
    for s in serials:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(int( s, 16)).revocation_date(
        datetime.datetime.today()
        ).build()
        builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(issCaKey, algorithm = hashAlgo)

    crlFileName = ((Path( basePath)) / issuerShortName) / "filePEM.crl"

    with open(crlFileName, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.PEM))
    
 
    crlFileName = ((Path( basePath)) / issuerShortName) / "fileDER.crl"
    with open(crlFileName, "wb") as f:
        f.write(crl.public_bytes(serialization.Encoding.DER))

    certOut = x509Out(str( crlFileName),str( str(crl.fingerprint)), str( crl.issuer), "")
    jOut = json.dumps(certOut)
    return jOut
    

def createNewTlsCsrFile(subjectShortName: str, 
                        basePath: Path,
                        subjectPassphrase = None,
                        keysize = 2048,
                        hashAlgo = hashes.SHA256(),
                        theSans: list = None
                        ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    os.mkdir(thePath)

    #create key and key file
    if keysize in [1024, 2048, 4096]:
        thisOneKey = newRSAKeyPair(keysize)
    else:
        thisOneKey = newECCKeyPair(keysize)

    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign
    theCsrWeNeed = createNewCsrObjTLS(thisOneKey, subjectShortName, hashAlgo, theSans)

    fileName = thePath / "file.csr"
    with open(fileName, "wb") as f:
            f.write(theCsrWeNeed.public_bytes(
            encoding=serialization.Encoding.PEM),
            )
    print("Your CSR file is {}".format(fileName))

    return fileName


def createNewCaCsrFile(subjectShortName: str, 
                        basePath: Path,
                        subjectPassphrase = None,
                        keysize = 4096,
                        hashAlgo = hashes.SHA256()
                        ):
    
    if subjectPassphrase != None:
        subjectPassphrase = (subjectPassphrase)

    #create the folder for the sub
    thePath = (Path( basePath)) / subjectShortName
    os.mkdir(thePath)

    #create key and key file
    thisOneKey = newRSAKeyPair(keysize)
    thisOneKey = keyToPemFile(thisOneKey, thePath / "key.pem", subjectPassphrase)
    
    #we have key and folder create CSR and sign

    #createNewCsrSubjectAndSignOnly
    theCsrWeNeed = createNewCsrSubjectAndSignOnly(thisOneKey, subjectShortName, hashAlgo)

    fileName = thePath / "file.csr"
    with open(fileName, "wb") as f:
            f.write(theCsrWeNeed.public_bytes(
            encoding=serialization.Encoding.PEM),
            )
    print("Your CSR file is {}".format(fileName))

    return fileName

        

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
            theRes = None
            fullName = Path(r) / file

            if fullName.suffix.lower() != ".pem":
                continue
            
            if fullName.parts[-1] == "key.pem":
                continue

            if fullName.parts[-1] == "certwithchain.pem":
                continue
            #todo.  need to not read other chain files
            
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
        
        try:
            cFile = open(file, "rb")
            databack = cFile.read()
            
            bob = x509.load_pem_x509_certificate(databack, default_backend())
            certs.append(bob)
            cFile.close()
            return certs
        except Exception as e:
            try:
                cFile = open(file, "rb")
                databack = cFile.read()
                
                bob = x509.load_der_x509_certificate(databack, default_backend())
                certs.append(bob)
                cFile.close()
                return certs
            except Exception as e:
                #probbly not pkcs7
                print("{} is not a PEM or DER cert file".format(file))
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

            #def verify(self, signature, data, padding, algorithm):
            #def verifier(self, signature, padding, algorithm):

            try:
                if isinstance(signer_public_key, rsa.RSAPublicKey):
                    verifier = signer_public_key.verify(
                        signature_bytes, child.tbs_certificate_bytes,  padding.PKCS1v15(), signature_hash_algorithm
                    )
                elif isinstance(signer_public_key, ec.EllipticCurvePublicKey):
                    verifier = signer_public_key.verify(
                        signature_bytes, child.tbs_certificate_bytes, ec.ECDSA(signature_hash_algorithm)
                    )
                else:
                    verifier = signer_public_key.verify(
                        signature_bytes, child.tbs_certificate_bytes, signature_hash_algorithm
                    )
                return isThatYouDad
            except:
                pass

            #if isinstance(signer_public_key, rsa.RSAPublicKey):
            #    verifier = signer_public_key.verifier(
            #        signature_bytes, padding.PKCS1v15(), signature_hash_algorithm
            #    )
            #elif isinstance(signer_public_key, ec.EllipticCurvePublicKey):
            #    verifier = signer_public_key.verifier(
            #        signature_bytes, ec.ECDSA(signature_hash_algorithm)
            #    )
            #else:
            #    verifier = signer_public_key.verifier(
            #        signature_bytes, signature_hash_algorithm
            #    )

            #verifier.update(child.tbs_certificate_bytes)
            #try:
            #    verifier.verify()
            #    return isThatYouDad
            #except:
            #    #do nothing
            #    pass
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

def createOrderedCertChain(certs : list, basePath: Path) -> list:
    """
    Takes in a cert or list of certs. Finds the entity cert to start the chain. Then builds the chain, first from cacerts list, if applicable.
    Then trying AIA, and finally the Mozilla root list as needed.
    returns the chain as a list of certs with the entity first and including the root.

    """
    ordList = list()
    root = None
    entityCert = None
    entCount = 0
    hasCA = False

    #make sure we have only one leaf cert and make it the start of the chain
    for cer in certs:
        if not bIsCA(cer):
            entityCert = cer
            entCount += 1
            ordList.append(entityCert)
        else:
            hasCA = True
        if cer.issuer.rfc4514_string() == cer.subject.rfc4514_string():
            root = cer
            
    if entCount > 1:
        raise Exception("There is more than one entity certificate in the collection. You must process manually") 

    if entCount == 0:
        if(len(certs) ==1 and hasCA):
            #there is one CA that is not a root. It desrves a chain
            entityCert = certs[0]
        else:
            raise Exception("There is no entity certificate in the collection. You must process manually. You may have the wrong file") 

    #the found leaf is the child for now
    child = entityCert
    while(True):
        
        parent = findParentCertInList(child, loadCertsFromFolder(basePath))
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

def buildChain(certIn: x509.Certificate, shortName, basePath: Path):
    try:
        folderCerts = loadCertsFromFolder(basePath)
        theList = list()
        theList.append(certIn)
        orderedCerts = createOrderedCertChain(theList, basePath)

        #cert with chain
        strOfPEMs = certListToCaTopDownPEM(orderedCerts)

        outFile = (basePath / shortName) / "certwithchain.pem"
            
        if os.path.isfile(outFile):
            os.remove(outFile)
        wFile = open(outFile, "w")
        wFile.write(strOfPEMs)
        wFile.close()

        #just chian.

        if(len(orderedCerts) > 1):
            del orderedCerts[0]

        strOfPEMs = certListToCaTopDownPEM(orderedCerts)

        outFile = (basePath / shortName) / "chain.pem"
            
        if os.path.isfile(outFile):
            os.remove(outFile)
        wFile = open(outFile, "w")
        wFile.write(strOfPEMs)
        wFile.close()
    except Exception as rr:
        raise rr

def signCsrNoQuestionsTlsServer(csrFile:Path(), 
                                issuerShortName: str, 
                                basePath: Path,
                                issuerPassphrase = None, 
                                pathLen = None , 
                                validFrom: datetime = CommonDateTimes.dtMinusTenMin , 
                                validTo: datetime = CommonDateTimes.dtPlusOneYear,
                                hashAlgo = hashes.SHA256(),
                                addSANs: bool = True,
                                isAcA: bool = False  ):
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
                print("{} is neither PEM or DER".format(csrFile))
                raise

        #should have a csr here
        #make it into a cert object for signing
        
        subjectShortName = getCnFromRDN(csr.subject)
        #create the folder for the sub
        thePath = (Path( basePath)) / subjectShortName
        if os.path.isdir(thePath):
            pass
        else:
            os.mkdir(thePath)

        theCsrWeNeed = csr
        issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
        issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
        subCertFileName = thePath / "cert.pem"

        #look for AIA and CDP files in the issuer folder
        aias = list()
        if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
            f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
            for m in f:
                aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
            f.close()
       
        cdps = list()
        if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
            f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
            for m in f:
                cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
            f.close()

        theTlsCert = signTlsCsrWithCaKeyWithSans(theCsrWeNeed, issCert, issCaKey, cdps, aias, pathLen, validFrom, validTo, hashAlgo, addSANs, isAcA )
        
        # Write our certificate out to disk.
        with open(subCertFileName, "wb") as f:
            f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))

        #also do a fun named cer verions
        fileName = getFileNameFromCert(theTlsCert)
        with open(thePath / fileName, "wb") as f:
            f.write(theTlsCert.public_bytes(serialization.Encoding.PEM))
        
        buildChain(theTlsCert, subjectShortName)

        #toissued folder of issuer
        #as needed add the issuer issued folder and add the cert to that folder
        issued = ((Path( basePath)) / issuerShortName) / "issued"
        if os.path.isdir(issued):
            pass
        else:
            os.mkdir(issued)
    
        with open(issued / fileName, "wb") as f:
            f.write(theTlsCert.public_bytes(serialization.Encoding.DER))


def signCsrNoQuestionsSubCA(csrFile:Path(), 
                        issuerShortName: str, 
                        basePath: Path,
                        issuerPassphrase = None,
                        pathLen = None , 
                        validFrom: datetime = CommonDateTimes.dtMinusTenMin , 
                        validTo: datetime = CommonDateTimes.dtPlusOneYear,
                        hashAlgo = hashes.SHA256(),
                        isAcA: bool = True  
                        ):
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

        subjectShortName = getCnFromRDN(csr.subject)
        #create the folder for the sub
        thePath = (Path( basePath)) / subjectShortName
        if os.path.isdir(thePath):
            pass
        else:
            os.mkdir(thePath)


        theCsrWeNeed = csr
        issCert = readCertFile(((Path( basePath)) / issuerShortName) / "cert.pem")
        issCaKey = readPemPrivateKeyFromFile(((Path( basePath)) / issuerShortName) / "key.pem", issuerPassphrase)
        subCertFileName = thePath / "cert.pem"

        #look for AIA and CDP files in the issuer folder
        aias = list()
        if os.path.isfile((((Path( basePath)) / issuerShortName) / "aia.txt")):
            f = open((((Path( basePath)) / issuerShortName) / "aia.txt"), "r")
        
            for m in f:
                aias.append(x509.AccessDescription(x509.ObjectIdentifier("1.3.6.1.5.5.7.48.2"), x509.UniformResourceIdentifier( m)))
            f.close()
       
        cdps = list()
        if os.path.isfile((((Path( basePath)) / issuerShortName) / "cdp.txt")):
            f = open((((Path( basePath)) / issuerShortName) / "cdp.txt"), "r")
        
            for m in f:
                cdps.append(x509.DistributionPoint(full_name=  [x509.UniformResourceIdentifier(m)], relative_name = None, reasons = None, crl_issuer = None))
            f.close()



        theCaCertBack = signSubCaCsrWithCaKey(theCsrWeNeed, issCert, issCaKey, cdps, aias, validFrom.value, validTo.value, pathLen, hashAlgo, isAcA)
        #theCaCertBack =  signTlsCsrWithCaKeyNoAddSan(theCsrWeNeed, issCert, issCaKey)
        # Write our certificate out to disk.
        with open(subCertFileName, "wb") as f:
            f.write(theCaCertBack.public_bytes(serialization.Encoding.PEM))

        #also do a fun named cer verions
        fileName = getFileNameFromCert(theCaCertBack)
        with open(thePath / fileName, "wb") as f:
            f.write(theCaCertBack.public_bytes(serialization.Encoding.PEM))
        
        #toissued folder of issuer
        #as needed add the issuer issued folder and add the cert to that folder
        issued = ((Path( localPath)) / issuerShortName) / "issued"
        if os.path.isdir(issued):
            pass
        else:
            os.mkdir(issued)
    
        with open(issued / fileName, "wb") as f:
            f.write(theCaCertBack.public_bytes(serialization.Encoding.DER))

        buildChain(theCaCertBack, subjectShortName)


def createCPSPols(preSignedData: cryptography.x509.base.CertificateBuilder, theUrl: str = "https://github.com/markgamache/labPkiPy/blob/master/cps.txt"):
    cpsoid = x509.ObjectIdentifier(x509.oid.CertificatePoliciesOID.CPS_QUALIFIER.dotted_string)
    qualifiers = []
    qualifiers.append(theUrl)
    pinfo = x509.PolicyInformation(cpsoid, qualifiers)
        
    return [pinfo]


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
    
    
    hash = hashes.SHA256()
    keysize = 2048
    isItaCA = ""
    pathlength = None
    noEKUs = False
    basepath = ""
    noSANs = ""
    allowedNames = list()
    disallowedNames = list()
    noKUs = False
    KUs = list()
    EKUs = list()
    cpsURL = "https://github.com/markgamache/labPkiPy/blob/master/cps.txt"
    theSans = list()


    try:
        opts, args = getopt.getopt(argv,"hm:n:vs:c:", ["mode=", 
                                                        "help", 
                                                        "name=", 
                                                        "signer=", 
                                                        "csr=", 
                                                        "verbose", 
                                                        "hash=", 
                                                        "validfrom=", 
                                                        "validto=", 
                                                        "keysize=", 
                                                        "isca=", 
                                                        "pathlength=", 
                                                        "noeku",
                                                        "ekus=",
                                                        "noku",
                                                        "kus=",
                                                        "basepath=",
                                                        "nosans",
                                                        "sans=",
                                                        "ncallowed=",
                                                        "ncdisallowed=",
                                                        "cps="])
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

            elif arg == Mode.NewLeafClient.name:
                currentMode =  Mode.NewLeafClient

            elif arg == Mode.NewSubCaClientAuth.name:
                currentMode =  Mode.NewSubCaClientAuth

            else:
                print("Your mode must be NewRootCA, NewSubCA, NewSubCaFromCSR, NewTlsFromCSR, SignCRL, CreateTlsCsr, CreateCaCSR,  or NewLeafTLS")
                print(syntax)
                sys.exit()

        elif opt =="--isca":
            if arg[0].lower() == "t": 
                isItaCA = True
            elif arg[0].lower() == "f":  
                 isItaCA = False
            else:
                print("isca is not right, must be true or false. Useing the RFC defualts")    

        elif opt == "--sans":
             #split list
            tempSans = arg.split(",")
            for oSan in tempSans:
                theSans.append( x509.DNSName(oSan.strip()))

        elif opt == "--noeku":
             noEKUs = True

        elif opt == "--cps":
             cpsURL = arg

        elif opt == "--noku":
             noKUs = True

        elif opt == "--ekus":
             #split list
            ekuTrys = arg.split(",")
            for tName in ekuTrys:
                if tName.strip() == "SERVER_AUTH":
                    EKUs.append(tName.strip())
                elif tName.strip() == "CLIENT_AUTH":
                    EKUs.append(tName.strip())  
                elif tName.strip() == "CODE_SIGNING":
                    EKUs.append(tName.strip())
                elif tName.strip() == "EMAIL_PROTECTION":
                    EKUs.append(tName.strip())
                elif tName.strip() == "TIME_STAMPING":
                    EKUs.append(tName.strip())  
                elif tName.strip() == "OCSP_SIGNING":
                    EKUs.append(tName.strip())
                elif tName.strip() == "ANY_EXTENDED_KEY_USAGE":
                    EKUs.append(tName.strip())
                else:
                    print("{} is not a valid EKU".format(tName))
                    print(syntax )
                    sys.exit(2)
  
        elif opt == "--kus":
             #split list
            kuTrys = arg.split(",")
            for tName in kuTrys:
                if tName.strip() == "digital_signature":
                    KUs.append(tName.strip())
                elif tName.strip() == "content_commitment":
                    KUs.append(tName.strip())  
                elif tName.strip() == "key_encipherment":
                    KUs.append(tName.strip())
                elif tName.strip() == "data_encipherment":
                    KUs.append(tName.strip())
                elif tName.strip() == "key_agreement":
                    KUs.append(tName.strip())  
                elif tName.strip() == "key_cert_sign":
                    KUs.append(tName.strip())
                elif tName.strip() == "crl_sign":
                    KUs.append(tName.strip())
                elif tName.strip() == "encipher_only":
                    KUs.append(tName.strip())
                elif tName.strip() == "decipher_only":
                    KUs.append(tName.strip())
                else:
                    print("{} is not a valid Key Usage".format(tName))
                    print(syntax )
                    sys.exit(2)

        elif opt == "--ncallowed":
             nameses = arg.split(",")
             for nm in nameses:
                allowedNames.append(nm)
                
        elif opt == "--ncdisallowed":
             nameses = arg.split(",")
             for nm in nameses:
                disallowedNames.append(nm)

        elif opt == "--nosans":
             noSANs = True

        elif opt == "--basepath":
            if os.path.isdir(arg):
                basepath = Path( arg )
            else:
                print("Your base path is not a directory. Try again or leave it blank for the current dir")
                print(syntax)
                sys.exit(2)

        elif opt == "--pathlength":
            if arg == "None":
                pathlength = None
            try:
                lenVal = int(arg)
                pathlength = lenVal
            except:
                print("Your pathlength should be None or an integer. It was not. we are using None")

        elif opt == "-h" or opt == "--help":
            print(syntax)
            sys.exit()

        elif opt == "--keysize":
            #print("{} {}".format(keysize , type(keysize)))
            if arg == "1024" or arg == 1024:
                keysize = 1024
            elif arg == "4096" or arg == 4096:
                keysize = 4096
            elif arg == "2048" or arg == 2048:
                keysize = 2048
            elif arg == "256" or arg == 256:
                keysize = 256
            elif arg == "384" or arg == 384:
                keysize = 384
            elif arg == "521" or arg == 521:
                keysize = 521
            else:
                print("Your keysize is goofy. Choosing 2048 for you. Options are 1024, 2048, and 4096")
                keysize = 2048

        elif opt == "--validfrom":
            global vFrom
            if arg == "janOf2018":
                vFrom = CommonDateTimes.janOf2018.value
            elif arg == "janOf2028":
                vFrom = CommonDateTimes.janOf2028.value
            elif arg == "janOf2048":
                vFrom = CommonDateTimes.janOf2048.value
            elif arg == "dtMinusTenMin":
                vFrom = CommonDateTimes.dtMinusTenMin.value
            elif arg == "dtMinusOneHour":
                vFrom = CommonDateTimes.dtMinusOneHour.value
            elif arg == "dtMinusTwoYears":
                vFrom = CommonDateTimes.dtMinusTwoYears.value
            elif arg == "dtPlusTenMin":
                vFrom = CommonDateTimes.dtPlusTenMin.value
            elif arg == "dtPlusOneYear":
                vFrom = CommonDateTimes.dtPlusOneYear.value
            elif arg == "dtPlusFiveYears":
                vFrom = CommonDateTimes.dtPlusFiveYears.value
            elif arg == "dtPlusTenYears":
                vFrom = CommonDateTimes.dtPlusTenYears.value
            elif arg == "dtPlusTwentyYears":
                vFrom = CommonDateTimes.dtPlusTwentyYears.value
            elif arg == "now":
                vFrom = CommonDateTimes.now.value
            elif arg == "marchOf2018":
                vFrom = CommonDateTimes.marchOf2018.value
            else:
                pass
        
        elif opt == "--validto":
            global vTo
            if arg == "janOf2018":
                vTo = CommonDateTimes.janOf2018.value
            elif arg == "janOf2028":
                vTo = CommonDateTimes.janOf2028.value
            elif arg == "janOf2048":
                vTo = CommonDateTimes.janOf2048.value
            elif arg == "dtMinusTenMin":
                vTo = CommonDateTimes.dtMinusTenMin.value
            elif arg == "dtMinusOneHour":
                vTo = CommonDateTimes.dtMinusOneHour.value
            elif arg == "dtMinusTwoYears":
                vTo = CommonDateTimes.dtMinusTwoYears.value
            elif arg == "dtPlusTenMin":
                vTo = CommonDateTimes.dtPlusTenMin.value
            elif arg == "dtPlusOneYear":
                vTo = CommonDateTimes.dtPlusOneYear.value
            elif arg == "dtPlusFiveYears":
                vTo = CommonDateTimes.dtPlusFiveYears.value
            elif arg == "dtPlusTenYears":
                vTo = CommonDateTimes.dtPlusTenYears.value
            elif arg == "dtPlusTwentyYears":
                vTo = CommonDateTimes.dtPlusTwentyYears.value
            elif arg == "now":
                vTo = CommonDateTimes.now.value
            elif arg == "marchOf2018":
                vTo = CommonDateTimes.marchOf2018.value
            else:
                pass    

        #signer
        elif opt == "-s" or opt == "--signer":
            global signerCN  
            signerCN = arg

        #csr to sign
        elif opt == "-c" or opt == "--csr":
            #see if the file is legit
            global csrFile
            csrFile = arg

        elif opt == "-v" or opt == "--verbose":
            verbose = True

        elif opt == "--hash":
            if arg == "SHA1":
                hash = hashes.SHA1()
            elif arg == "MD5":
                hash = hashes.MD5()
            elif arg == "SHA512":
                hash = hashes.SHA512()
            else:
                hash = hashes.SHA256()
        else:
            print("{} is not a valid argument or flag".format(opt))


    global localPath
    localPath = Path( os.path.abspath(os.path.dirname(sys.argv[0])))
    if basepath == "":
        basepath = localPath           

    #testing region begin
    

    aBunchOfTests = """

    createNewRootCA("bob", basepath, None, 4096, CommonDateTimes.janOf2018.value, CommonDateTimes.janOf2048.value, 2, hash, True, ["cats.com", "pkilab.markgamache.com"], ["bofa.com"])
    createNewSubCA("fred", "bob", basepath, None, None, 2048, CommonDateTimes.janOf2018.value, CommonDateTimes.janOf2048.value, 1, hashes.SHA256(), True, list())
    createNewTlsCert("walter.pkilab.markgamache.com", "fred", basepath, None, None, 2048, CommonDateTimes.dtMinusTenMin.value , CommonDateTimes.dtPlusTenMin.value)

    www = createNewRootCA("bob", basepath, None, 4096, CommonDateTimes.janOf2018.value, CommonDateTimes.janOf2048.value, 2)
    
    createNewSubCAClientAuth("cliAuthCA", "bob", basepath, None, None, 4096, CommonDateTimes.janOf2018, CommonDateTimes.janOf2048, 2, hash, True )
    tlsCSR = createNewTlsCsrFile("www.fattire.com", basepath, None, keysize, hash)
    signCsrNoQuestionsTlsServer(tlsCSR, "bob", basepath, None, None, CommonDateTimes.dtMinusTenMin , CommonDateTimes.dtPlusTenMin, hash, False, False)

    newCACSR =  createNewCaCsrFile("floatingCA", basepath, None, keysize, hash)
    signCsrNoQuestionsSubCA(newCACSR, "bob", basepath, None, pathlength, CommonDateTimes.dtMinusTenMin , CommonDateTimes.dtPlusTenMin, hash, True)

    createCRL("bob", basepath, None, CommonDateTimes.janOf2018, CommonDateTimes.janOf2048)

    createNewSubCA("ted", "bob", basepath, None, None, 4096, CommonDateTimes.janOf2018, CommonDateTimes.janOf2028 ,1)
    createCRL("ted", basepath, None, CommonDateTimes.janOf2018, CommonDateTimes.janOf2048)

    createNewSubCA("fred", "bob", basepath)

    createNewTlsCert("www.fun.com", "fred", basepath, None, None, 2048, CommonDateTimes.dtMinusTenMin , CommonDateTimes.dtPlusTenMin)

    createNewTlsCertNoEKUs("www.cats.com", "fred", basepath, None, None, 1024, CommonDateTimes.dtMinusTenMin , CommonDateTimes.dtPlusTenMin, hashes.MD5())

    createNewClientCert("bobs client", "fred", localPath, None, None, 2048, CommonDateTimes.dtMinusTenMin , CommonDateTimes.dtPlusTenMin, hash)    
    """
    #testing region end


    #magic begins here
    
    #check a couple of possible switch conflicts 
    if noKUs and len(KUs) > 0:
        print("You can't set --noku and --kus")
        print(syntax)
        sys.exit(2)

    if noEKUs and len(EKUs) > 0:
        print("You can't set --noeku and --ekus")
        print(syntax)
        sys.exit(2)

    if noSANs and len(theSans) > 0:
        print("You can't set --nosans and --sans")
        print(syntax)
        sys.exit(2)



    #pre-checks done
    
    if currentMode == None:
        print("Your -m or --mode must be set")
        print("Your mode must be NewRootCA, NewSubCA, NewSubCaFromCSR, NewTlsFromCSR, SignCRL, CreateTlsCsr, CreateCaCSR, or NewLeafTLS")
        print(syntax)
        sys.exit()

    if currentMode == Mode.NewRootCA:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            if isItaCA == "":
                isItaCA = True
            #print("About to make Root CA {} in {} keysize {} of type {}".format(subjectCN, basepath, keysize, type(keysize)))
            certbk = createNewRootCA(subjectCN, basepath, None, keysize, vFrom, vTo, pathlength, hash, isItaCA, allowedNames, disallowedNames, KUs, EKUs, cpsURL)
            print(certbk)
            sys.exit()
        
    if currentMode ==  Mode.NewSubCA:
        if subjectCN == "blank" or signerCN == "blank":  
            print("Your -n or --name must be set and -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            if isItaCA == "":
                isItaCA = True
            certbk = createNewSubCA(subjectCN, signerCN, basepath, None, None, keysize, vFrom, vTo, pathlength, hash, isItaCA , allowedNames, disallowedNames, KUs, EKUs, cpsURL)
            print(certbk)
            sys.exit()

    if currentMode == Mode.NewLeafTLS:
        if subjectCN == "blank" or signerCN == "blank":  
            print("Your -n or --name must be set and -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            if isItaCA == "":
                isItaCA = False

            if noSANs == "" and len(theSans) == 0:
                theSans.append(subjectCN)

            certbk = createNewTlsCert(subjectCN, signerCN, basepath, None, None, keysize, vFrom, vTo, hash, noSANs, isItaCA, noEKUs, KUs, EKUs, cpsURL, theSans)
            print(certbk)
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
            if isItaCA == "":
                isItaCA = False

            signCsrNoQuestionsTlsServer(Path(csrFile) , signerCN, basepath, None, pathlength, vFrom, vTo, hash, noSANs, isItaCA)   
            print("Signed CSR {}\n\r".format(csrFile))
            sys.exit()
            
    if currentMode == Mode.SignCRL:
        if  signerCN == "blank":  
            print("Your -s or --signer must be set")  
            print(syntax)
            sys.exit()
        else:
            crlBack = createCRL(signerCN, basepath, None, vFrom, vTo, hash)
            print(crlBack)
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
            if isItaCA == "":
                isItaCA = True

            signCsrNoQuestionsSubCA(Path(csrFile), signerCN, basepath, None, pathlength, vFrom, vTo, hash, isItaCA)
            print("Signed CSR for Sub CA for  {}\n\r".format(csrFile))
            sys.exit()
                        
    if currentMode == Mode.CreateCaCSR:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            createNewCaCsrFile(subjectCN, basepath, None, keysize, hash)
            print("Created CA CSR for {}\n\r".format(subjectCN))
            sys.exit()

    if currentMode == Mode.CreateTlsCsr:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            if noSANs == "" and len(theSans) == 0:
                theSans.append(subjectCN)

            createNewTlsCsrFile(subjectCN, basepath, None, keysize, hash, theSans)
            print("Created TLS CSR for {}\n\r".format(subjectCN))
            sys.exit()

    if currentMode == Mode.NewLeafClient:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            if isItaCA == "":
                isItaCA = False

            cliback = createNewClientCert(subjectCN, signerCN, basepath, None, None, pathlength, keysize, vFrom, vTo, hash, noSANs, isItaCA, KUs, EKUs)
            print(cliback)
            sys.exit()

    if currentMode == Mode.NewSubCaClientAuth:
        if subjectCN == "blank":
            print("Your -n or --name must be set")
            print(syntax)
            sys.exit()
        else:
            if isItaCA == "":
                isItaCA = True
            caBack = createNewSubCAClientAuth(subjectCN, signerCN, basepath, None, None, keysize, vFrom, vTo, pathlength, hash, isItaCA, allowedNames, disallowedNames, KUs, EKUs )
            print(caBack)
            sys.exit()
            
    print("Not sure how we got here. I hope you can read and write Python")
    sys.exit()
 


if __name__ == "__main__":
    main(sys.argv[1:])
 