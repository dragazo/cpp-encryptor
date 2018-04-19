#ifndef ENCRYPTION_H
#define ENCRYPTION_H

// type used for storing bit info
typedef std::int_fast16_t fint;

// typedef for function pointer to encryptor or decryptor
typedef void(*processor_t)(char *data, fint **masks, fint maskc, fint offset, fint length, fint maskoffset);

// encrypts the given data
void encrypt(char *data, fint **masks, fint maskc, fint offset, fint length, fint maskoffset);
// decrypts the given data
void decrypt(char *data, fint **masks, fint maskc, fint offset, fint length, fint maskoffset);

// encrypts or decrypts the given file to the specified output
void encrypt_decrypt(const char *in_path, const char *out_path, const char *key, processor_t processor);

#endif
