#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>

// takes a string and converts it into an array of sets of bitmask phase shifts.
// must use delete[] on the result to dispose
// key   - the string to use as the key
// maskc - the number of sets of bitmasks in the result
int* getmasks(const char *key, int &maskc);

// ------------------------------------------

// typedef for function pointer to encryptor or decryptor
// data       - the data array to encrypt
// masks      - the array of bitmask sets to use
// maskc      - the number of sets in the masks array
// offset     - the starting position in data array
// length     - the number of bytes to process
// maskoffset - the starting index of the mask set to use
typedef void(*crypto_t)(char *data, int *masks, int maskc, int offset, int length, int maskoffset);

// encrypts the specified binary array with an array of mask sets (as from getmasks)
void encrypt(char *data, int *masks, int maskc, int offset, int length, int maskoffset);
// encrypts the specified binary array with an array of mask sets (as from getmasks)
void decrypt(char *data, int *masks, int maskc, int offset, int length, int maskoffset);

// ------------------------------------------

// encrypts or decrypts the given file
// in     - the input stream
// out    - the output stream
// key    - the key to use
// crypto - the encrypt/decrypt function to use
// log    - the destination for log messages (or null for ignore)
void cryptf(std::istream &in, std::ostream &out_path, const char *key, crypto_t crypto, std::ostream *log = nullptr);

#endif
