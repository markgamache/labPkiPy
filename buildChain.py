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

def loadCertsFromFolder(folderName : Path) -> list:
    dBack = list()
    for r, d, f in os.walk(folderName, topdown=False):
        #print(r)
        for file in f:
            fullName = Path(r) / file

            if fullName.suffix.lower() not in [".pem",".crt",".cer"]:
                continue
            
            #do work
            dBack.append( readCertFile(fullName)[0])

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

def readCertFile(file: Path) -> list:
    
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

def certListToCatdPEM(certs : list):
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



syntax = '-f filename \n-v verbose \n-h help \n-r reverse the chain \n-i included the leaf certificate \n-a analyze an input file. This shows the chain order in a human readable way\n\n'
syntax += 'example: \nbuildChain.py -f justCertDER.cer -v'
verbose =  False
certFile = ""
subject = ""
mozRoots = None
folderCerts = list()



def main(argv):
    
    global includeLeaf
    includeLeaf = False

    global reverseIt 
    reverseIt = False

    global analyzeFile
    analyzeFile =  False

    global forLTM
    forLTM = False

    try:
        opts, args = getopt.getopt(argv,"arhif:v",list())
    except getopt.GetoptError:
        print(syntax )
        sys.exit(2)
    
    for opt, arg in opts:
        if opt == "-f":
            global certFile
            certFile = Path( arg)
        elif opt == "-h":
            print(syntax)
            sys.exit()
        elif opt == "-i":
            includeLeaf = True
        elif opt == "-a":
            analyzeFile = True
        elif opt == "-r":
            reverseIt = True
        elif opt == "-v":
            global verbose
            verbose = True
        else:
            pass


    #magic begins here

    localPath = Path( os.path.abspath(os.path.dirname(sys.argv[0])))
    cacertsPath = localPath / "cacerts"

    global folderCerts
    folderCerts = loadCertsFromFolder(cacertsPath)

    if certFile == "":
        print("You must specify a cert file using -f\r\n")
        print( syntax)
        sys.exit(2)

    if not os.path.isfile(certFile):
        print("You must specify a cert file using -f\r\n")
        print( syntax)
        sys.exit(2)

    global mozRoots
    mozRoots = getMozillaRoots()
    #we need to figure out what the file really is.  Could be a p7b or cert in PEM or DER
    testOut = readP7BFile(certFile)
    
    if len(testOut) == 0:
        #try a chain of PEMs, as is common...
        try:
            hFile = open(certFile, "r")
            fData = hFile.read()
            hFile.close()
            testOut = parseCertsFromPEMs(fData)
        except Exception as pemEx:
            if pemEx.reason == "character maps to <undefined>":
                #probably just a binary file so can't be a PEM
                pass
            else:
                raise pemEx

    if len( testOut) == 0:
        #try as just a cert file
        testOut = readCertFile(certFile)

    if len(testOut) == 0:
        print("{} does not appear to be a cert file or pkcs7 file, in either PEM or DER.  Please have a look")
        sys.exit(2)

    if len(testOut) > 0:
        
        #if analyze
        if analyzeFile:
            analyzeChainFile(testOut)
            print("-a will not output a new file. If you want to output and see the chain data use -v")
        else:
        
            #was P7B or a cert in PEM or DER
            screen("{}'s basic structure is valid. Validating its content ".format(certFile))
            orderedCerts = createOrderedCertChain(testOut)
            certCN = getCnFromRDN(orderedCerts[0].subject)
            certSerial = str(hex(orderedCerts[0].serial_number))
            stubSer = certSerial[-5:-1]
            if not includeLeaf:
                del orderedCerts[0]

            if reverseIt:
                orderedCerts.reverse()
            

            screen("Cert is {}".format(certCN))
            
            
            strOfPEMs = certListToCatdPEM(orderedCerts)

            #name the file
            certCN = certCN.replace(' ', "")
            if includeLeaf:
                outFile = localPath / "{}_{}_chain_w_leaf.pem".format(certCN, stubSer) 
            else:
                outFile = localPath / "{}_{}_chain.pem".format(certCN, stubSer) 

            
            if os.path.isfile(outFile):
                os.remove(outFile)
            wFile = open(outFile, "w")
            wFile.write(strOfPEMs)
            wFile.close()
            print("Your chain file is named {}".format(outFile))

            if verbose:
                analyzeChainFile(orderedCerts)

       

if __name__ == "__main__":
    main(sys.argv[1:])
    
