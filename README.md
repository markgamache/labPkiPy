# labPkiPy
pki lab. Never use for prod.  Probably weak RNG, obviously no HSM, and no passwords currently

the lab design is for various testing purposes. 

The current state is mostly related to positive test cases, however some of the code is in place to test if/how various TLS clients process config errors like:
*improper path len
*violated name constraints 
*very long path len
*wrong AIAs
*Many AIAs
*CDP issues
*Name constraints use
*Name constraints violations 
*EKU mistakes 

