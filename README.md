# PHP TSA (TimeStamping authority)
## Description
RFC3161 TSA (TimeStamping authority) server with pure php.  
### Settings
``$tsa->policy`` TSA Policy Object id  
``$tsa->serial`` TSA serial number  
``$tsa->hashAlgorithm`` TSA hash algorithm (md2, md4, md5, sha, sha1, sha224, sha256, sha384, sha512)  
``$tsa->signerCert`` TSA signer certificate  
``$tsa->signerPkey`` TSA signer privatekey  
``$tsa->extracerts`` array containts TSA signer extra certificate to included (ca chain of issuers)  
