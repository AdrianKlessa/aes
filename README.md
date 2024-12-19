
### Disclaimer:

### This code is not safe for real-world usage

*The implementations are for educational purposes*

*They are slow, don't use proper sources of entropy and are surely vulnerable to timing and various other attacks*


## Resources used:

* [NIST FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) for implementation details and test vectors for intermediate stages of encryption
* [NIST SP 800-38a](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf) for test vectors for CBC mode
* [AES lecture slides](https://tratliff.webspace.wheatoncollege.edu/2016_Fall/math202/inclass/sep21_inclass.pdf) by T. Ratliff at Wheaton College for verifying the multiplicative inverse in GF(2^8)
* [The Wikipedia article](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) for a high-level explanation of the algorithm and information about equivalent implementation methods