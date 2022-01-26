# labPkiPy
pki lab. Never use for prod.  Probably weak RNG, obviously no HSM, and no passwords currently

the lab design is for various testing purposes. 

The current state is mostly related to positive test cases, however some of the code is in place to test if/how various TLS clients process config errors like:

*improper path len

*violated name constraints (not there yet)

*very long path len

*wrong AIAs

*Many AIAs

*CDP issues

*Name constraints use

*Name constraints violations 

*EKU mistakes 

*SSL cert signed by SSL certs, etc.


AIAs are stamped based on a file in the issuer folder called aia.txt
CDPs are stamped based on a file in the issuer folder called cdp.txt
Revoked cert CNs are stamped based on a file in the issuer folder called revoked.txt. They should be the serials, in hex, one more line

Run the TestTool.py to see all the magic

Besides the self contained functionality, it can create CSRs for TLS and CAs as well as sign incoming CSRs for TLS CAs.


