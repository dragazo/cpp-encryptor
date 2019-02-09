#ifndef DRAGAZO_ENCRYPTION_H
#define DRAGAZO_ENCRYPTION_H

#include <iostream>
#include <thread>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>

// represents a parallel encryption/decryption pipeline.
// has methods for processing arbitrary blocks of memory or entire streams/files.
// all operations are performed in-place.
class crypto_service
{
private: // -- helper types -- //

	// represents a raw (and single-threaded) encryption/decryption function to call in parallel
	typedef void(*crypto_func_t)(char *data, const int *masks, int maskc, int offset, int length, int maskoffset);

	// represents an encryption/decryption worker thread
	struct worker_thread_t
	{
		bool ready; // marks if this worker is ready to do something
		std::thread thread; // thread handle for the worker
	};

	class mask_set
	{
	private: // -- data -- //

		std::vector<int> masks;

	public: // -- ctor / dtor / asgn -- //

		explicit mask_set(const char *key);

	public: // -- access -- //

		// returns the number of masks - each mask is an array of 8 values used for bitwise phase shifts
		std::size_t count() const noexcept { return masks.size() / 8; }

		// returns a pointer to the flattened array of masks - think of it as a count() x 8 flattened array of phase shifts
		int *get() noexcept { return masks.data(); }
	};

private: // -- management data -- //

	std::mutex sync_mutex;             // mutex used for worker thread synchronization
	std::condition_variable main_cv;   // condition that the main thread waits on (manages the others)
	std::condition_variable worker_cv; // condition that the worker threads wait on

	bool workers_alive; // marks that the workers should still be alive
	bool workers_dirty; // marks that the workers have dirty info that should be updated before they begin (e.g. local of masks)
	std::size_t workers_done; // number of workers that have completed their operation (managed by workers)

	std::size_t workerc; // number of workers
	std::unique_ptr<worker_thread_t[]> workers; // worker thread handle array

private: // -- manager shared resources -- //

	char       *data;   // data array (not allocated by us)
	std::size_t length; // total length of the data array to process
	std::size_t width;  // width of a data slice

private: // -- data -- //

	crypto_func_t crypto_func; // the encryption/decryption function to use
	mask_set      masks;       // mask sets - flattened maskc x 8 array
	std::size_t   maskoff;      // mask set offset

public: // -- enums -- //

	enum class mode
	{
		encrypt, decrypt
	};

public: // -- ctor / dtor / asgn -- //

	// initializes the parallel crypto for work with the given password and mode.
	// this is equivalent to calling setkey() and setmode() - throws any exception those would throw.
	crypto_service(const char *key, mode m);

	~crypto_service();

	crypto_service(const crypto_service&) = delete;
	crypto_service(crypto_service&&) = delete;

	crypto_service &operator=(const crypto_service&) = delete;
	crypto_service &operator=(crypto_service&&) = delete;

public: // -- mode access -- //

	// sets the encrypt/decrypt mode.
	// this must be called before any calls to process() are made - can be modified later.
	// if m is an unknown mode, throws std::invalid_argument.
	void setmode(mode m);

	// sets the encryption/decryption key to use for all subsequient process requests.
	// this must be called before any calls to process() are made - can be modified later.
	// throws std::invalid_argument if key is null or empty
	void setkey(const char *key);

public: // -- raw crypto processing -- //

	// calls to process() remember the state after the last invocation to facilitate chunk processing.
	// this function resets that state information.
	// this should be used before processing a piece of unrelated information (e.g. a different file).
	void reset() noexcept;

	// processes the given data array in-place
	// data  - data buffer to process
	// start - index in array to begin
	// count - number of bytes to process
	void process(char *data, int start, int count);

public: // -- steam/file crypto processing -- //

	// encrypts or decrypts the input stream to the output stream
	// in     - the input stream
	// out    - the output stream
	// buffer - the buffer to use for io/processing operations
	// buflen - the length of the buffer
	// log    - the destination for log messages (or null for no logging)
	void process_stream(std::istream &in, std::ostream &out, char *buffer, int buflen, std::ostream *log = nullptr);

	// encrypts or decrypts the input file to the output file. returns true if there were no errors
	bool process_file(const char *in_path, const char *out_path, char *buffer, int buflen, std::ostream *log = nullptr);
	// encrypts or decrypts the specified file in-place. returns true if there were no errors
	bool process_file_in_place(const char *path, char *buffer, int buflen, std::ostream *log = nullptr);

	// recursively encrypts or decrypts the contents of the specified path in-place. returns the number of successful operations
	int process_file_in_place_recursive(const char *root_path, char *buffer, int buflen, std::ostream *log = nullptr);
};

#endif
