# lightweight-crypto
Compares security and performance of 4 novel lightweight encryption algorithms to standard AES across 5 message lengths and 4 GCC optimization levels. 

Novel algorithms:<br />
Elephant 160-bit: description found [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists); library used in tests found [here](https://github.com/TimBeyne/Elephant/tree/master/crypto_aead/elephant160v1/ref). <br />
Elephant 200-bit: description found [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists); library used in tests found [here](https://github.com/TimBeyne/Elephant/tree/master/crypto_aead/elephant200v2/ref). <br />
TinyJambu 128-bit: description and library used in tests found [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists). <br />
TinyJambu 192-bit: description and library used in tests found [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists). <br />
TinyJambu 256-bit: description and library used in tests found [here](https://csrc.nist.gov/Projects/lightweight-cryptography/finalists). <br />


AES: crypto++ implementation found [here](https://github.com/weidai11/cryptopp).
