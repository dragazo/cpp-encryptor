#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>
#include <thread>
#include <atomic>

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
typedef void(*crypto_t)(char *data, const int *masks, int maskc, int offset, int length, int maskoffset);

// encrypts the specified binary array with an array of mask sets (as from getmasks)
void encrypt(char *data, const int *masks, int maskc, int offset, int length, int maskoffset);
// encrypts the specified binary array with an array of mask sets (as from getmasks)
void decrypt(char *data, const int *masks, int maskc, int offset, int length, int maskoffset);

// ------------------------------------------

// wraps crypto functions to process in parallel
class ParallelCrypto
{
private: // private data (self-managed)

	bool               active;   // flags that this object is still in use
	int                threadc;  // number of threads
	std::thread       *threads;  // threads to use
	std::atomic<bool> *has_data; // settings for each thread

	char *data;  // data array (not allocated)
	int   width; // width of a data slice

public: // public data (user-managed)

	crypto_t crypto;  // the encryption function to use
	int     *masks;   // mask sets
	int      maskc;   // number of mask sets
	int      maskoff; // mask set offset

public:

	// initializes the parallel crypto for work.
	// this creates running thread objects, so try to do this as late as possible.
	ParallelCrypto();
	// stops threads and frees resources. destroying multiple times is safe.
	// this can be used immediately after work is completed to avoid worker threads in the background.
	// object is still usable after destruction (it just won't be parallel anymore)
	~ParallelCrypto();

	// processes the given data array in parallel
	// data  - data buffer to process
	// start - index in array to begin
	// count - number of bytes to process
	void process(char *data, int start, int count);
};

// ------------------------------------------

// encrypts or decrypts the input stream to the output stream
// in     - the input stream
// out    - the output stream
// worker - the parallel crypto worker it use (should already be set up for use). maskoff is set to 0 before use
// buffer - the buffer to use for io/processing operations
// buflen - the length of the buffer
// log    - the destination for log messages (or null for no logging)
void crypt(std::istream &in, std::ostream &out, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log = nullptr);

// encrypts or decrypts the input file to the output file. returns true if there were no errors
bool cryptf(const char *in_path, const char *out_path, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log = nullptr);
// encrypts or decrypts the specified file in-place. returns true if there were no errors
bool cryptf(const char *path, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log = nullptr);

// recursively encrypts or decrypts the contents of the specified path in-place. returns the number of successful operations
int cryptf_recursive(const char *root_path, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log = nullptr);

#endif
