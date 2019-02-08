#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <iostream>
#include <thread>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>

// wraps crypto functions to process in parallel
class ParallelCrypto
{
private: // -- helper types -- //

	// represents a raw (and single-threaded) encryption/decryption function to call in parallel
	typedef void(*crypto_t)(char *data, const int *masks, int maskc, int offset, int length, int maskoffset);

	// represents an encryption/decryption worker thread
	struct worker_thread_t
	{
		std::atomic<bool> has_data = false; // marks if this worker has work to do

		std::thread thread; // thread handle for the worker
	};

private: // -- private data (self-managed) -- //

	bool active;  // flags that this object is still in use
	
	std::size_t workerc; // number of workers
	std::unique_ptr<worker_thread_t[]> workers; // worker thread handle array

	

	char *data;  // data array (not allocated by us)
	std::size_t width; // width of a data slice

	crypto_t               crypto;  // the encryption function to use
	std::unique_ptr<int[]> masks;   // mask sets - flattened maskc x 8 array
	std::size_t            maskc;   // number of mask sets
	std::size_t            maskoff; // mask set offset

public: // -- enums -- //

	enum class mode
	{
		encrypt, decrypt
	};

public:

	// initializes the parallel crypto for work with the given password and mode.
	// this is equivalent to calling setkey() and setmode() - throws any exception those would throw.
	ParallelCrypto(const char *key, mode m);

	~ParallelCrypto();

	ParallelCrypto(const ParallelCrypto&) = delete;
	ParallelCrypto(ParallelCrypto&&) = delete;

	ParallelCrypto &operator=(const ParallelCrypto&) = delete;
	ParallelCrypto &operator=(ParallelCrypto&&) = delete;

	// sets the encrypt/decrypt mode.
	// this must be called before any calls to process() are made - can be modified later.
	// if m is an unknown mode, throws std::invalid_argument.
	void setmode(mode m);

	// sets the encryption/decryption key to use for all subsequient process requests.
	// this must be called before any calls to process() are made - can be modified later.
	// throws std::invalid_argument if key is null or empty
	void setkey(const char *key);

	// calls to process() remember the state after the last invocation to facilitate chunk processing.
	// this function resets that state information.
	// this should be used before processing a piece of unrelated information (e.g. a different file).
	void reset() noexcept;

	// processes the given data array in-place
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
