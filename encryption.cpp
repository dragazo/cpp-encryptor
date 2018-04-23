#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <filesystem>
#include "encryption.h"
#include "filesize.h"

// -- REMOVE THIS WHEN COMPILER IS UPDATED -- //
namespace std { namespace filesystem = std::experimental::filesystem; }
// ------------------------------------------ //

namespace fs = std::filesystem;

// rotates an 8-bit value v to the right by n bits
#define rot_8(v, n) ((v >> n) | (v << n) & 0xff)

// the size of the buffer used during encryption
constexpr int buffer_size = 1000000;

// a series of pre-loaded factorials
constexpr int F[]{1, 1, 2, 6, 24, 120, 720, 5040};

// -------------------------------

// gets the masks for an individual key
void getmasks(int key, int *dest)
{
	// create a list of powers of 2 (represents the bit mask phase shifts for each bit in a byte)
	std::vector<int> pos = {1, 2, 4, 8, 16, 32, 64, 128};
	key %= 40320; // there are only 8! possibilities, so ensure key is in that range

	// get all 8 bitmasks
	for (int i = 0; i < 8; ++i)
	{
		int res = key / F[7 - i];     // get the index of the bitmask
		dest[i] = pos[res];           // save it
		pos.erase(pos.begin() + res); // remove it from the list       
		key %= F[7 - i];              // reduce key to put it in range for the next pass
	}
}
int* getmasks(const char *key, int &maskc)
{
	maskc = strlen(key);            // get the string length
	if (maskc == 0) return nullptr; // return null on empty

	int *m = new int[maskc * 8]; // allocate the result

	// for each set of 8 masks
	for (int i = 0; i < maskc; ++i)
	{
		// get the raw key and next raw key
		int _key = key[i];
		int _next = key[(i + 1) % maskc];

		// interlace it with the next raw key
		_key ^= rot_8(_next, 4);

		// multiply to extend interval
		_key *= (key[i] ^ _key ^ _next) * 21143; // the literal is drawn from a large prime number to help evenly distribute resultant keys

		// get the masks for the interlaced key
		getmasks(_key, m + i * 8);
	}

	return m;
}

// -------------------------------

void encrypt(char *data, const int *masks, int maskc, int offset, int length, int maskoffset)
{
#define bitop(i) res |= ((set[i] & ch) != 0) << i

	int        res;                          // the result of one iteration
	const int *set = masks + maskoffset * 8; // the mask set to use
	int        ch;                           // the character being processed

	data += offset; // increment data up to start

	// for each byte up to len
	for (int i = 0; i < length; ++i, ++data)
	{
		res = 0;    // zero the result
		ch = *data; // get the character being processed

		// apply the phase shifts
		// macro inlining (potentially faster, depending on optimizer)
		bitop(0);
		bitop(1);
		bitop(2);
		bitop(3);
		bitop(4);
		bitop(5);
		bitop(6);
		bitop(7);

		// record the result
		*data = res;

		// next pass
		if ((set += 8) == masks + maskc * 8) set = masks;
	}

#undef bitop
}
void decrypt(char *data, const int *masks, int maskc, int offset, int length, int maskoffset)
{
#define bitop(i) res |= -((ch >> i) & 1) & set[i]

	int        res;                          // the result of one iteration
	const int *set = masks + maskoffset * 8; // the mask set to use
	int        ch;                           // the character being processed

	data += offset; // increment data up to start

	// for each byte up to len
	for (int i = 0; i < length; ++i, ++data)
	{
		res = 0;    // zero the result
		ch = *data; // get the character being processed

		// apply the phase shifts
		// macro inlining (potentially faster, depending on optimizer)
		bitop(0);
		bitop(1);
		bitop(2);
		bitop(3);
		bitop(4);
		bitop(5);
		bitop(6);
		bitop(7);

		// record the result
		*data = res;

		// next pass
		if ((set += 8) == masks + maskc * 8) set = masks;
	}

#undef bitop
}

// -------------------------------

// holds the settings used by a thread during a crypto cycle
struct CryptoSettings
{
	bool has_data;  // flags that there is data to process

	int start;      // the index in buffer to start at
	int width;      // the number of bytes to process
	int maskoffset; // the index of the mask to use for the first byte
};

void crypt(std::istream &in, std::ostream &out, const char *key, crypto_t crypto, std::ostream *log)
{
	// macro used for cleaning up after execution
	#define clean { running = false; for (int i = 0; i < threadc; ++i) threads[i].join(); delete[] threads; delete[] settings; delete[] masks; delete[] buffer; }

	// -- initialize data -- //

	std::streampos in_pos = in.tellg();   // the position in the input file (we need to store these in case in/out are the same file)
	std::streampos out_pos = out.tellp(); // the position in the output file

	std::streamsize progress = 0; // the number of bytes that have been processed
	std::streamsize total;        // total length of the file

	// get total length
	in.seekg(0, in.end);
	total = in.tellg() - in_pos;

	// compact the total length
	const char *total_units;
	double c_total = compact_filesize((double)total, total_units);

	// allocate the data buffer
	char *buffer = new char[buffer_size];

	// turn the key into masks
	int maskc;
	int *masks = getmasks(key, maskc);

	// get the number of threads to create (#processors that aren't us) (make sure it's not negative for some reason)
	const int threadc = std::max(std::thread::hardware_concurrency() - 1, 0u);

	// allocate the threads and settings
	std::thread *threads = threadc > 0 ? new std::thread[threadc] : nullptr;
	CryptoSettings *settings = threadc > 0 ? new CryptoSettings[threadc] : nullptr;

	// flag that marks that execution is going on
	bool running = true;
	
	// initialize the threads and settings
	for (int i = 0; i < threadc; ++i)
	{
		// initialize the settings object
		settings[i].has_data = false;

		// initialize the thread object
		threads[i] = (std::thread)([crypto, buffer, masks, maskc, &settings = settings[i], &running]()
		{
			// if we're still running
			while (running)
			{
				// if we have stuff to do
				if (settings.has_data)
				{
					// process the data
					crypto(buffer, masks, maskc, settings.start, settings.width, settings.maskoffset);
					// mark that we did it
					settings.has_data = false;
				}

				// might as well end our time slice (otherwise would just be a spin wait)
				std::this_thread::yield();
			}
		});
	}
	
	// -- and the fun begins -- //

	try
	{
		// loop over the mask offset (each pass consumes buffer_size, so increment by that)
		for (int offset = 0; ; offset = (offset + buffer_size) % maskc)
		{
			// seek read pos (required if in/out are the same file)
			in.seekg(in_pos);
			// read data from input
			in.read(buffer, buffer_size);

			// get the number of bytes read
			std::streamsize len = in.gcount();
			// if we read nothing, we're done
			if (len == 0) break;

			// get width of each slice for a thread
			std::streamsize width = len / (threadc + 1);
			// if width is positive, distribute work load to the threads
			if (width > 0) for (int i = 0; i < threadc; ++i)
			{
				// set up their workload
				settings[i].start = width * i;
				settings[i].width = width;
				settings[i].maskoffset = (offset + width * i) % maskc;

				// flag that they have data
				settings[i].has_data = true;
			}

			// we do the last slice ourselves
			crypto(buffer, masks, maskc, width * threadc, len - width * threadc, (offset + width * threadc) % maskc);

			// if we gave the threads work, wait for them to finish
			if (width > 0) for (int i = 0; i < threadc; ++i)
				while (settings[i].has_data) std::this_thread::yield();

			// clear out's state (reading to eof sets eof flag, which means we can't write the data back if in/out are the same file)
			out.clear();
			// seek write pos (required if in/out are the same file)
			out.seekp(out_pos);
			// write the result back to output
			out.write(buffer, len);
			
			// increment things as needed
			progress += len;
			in_pos += len;
			out_pos += len;

			// if logging enabled
			if (log)
			{
				// compact the progress size
				const char *progress_units;
				double c_progress = compact_filesize((double)progress, progress_units);

				// output progress and go back to start of line
				*log
					<< std::setprecision(1) << std::fixed << std::setw(6) << c_progress << progress_units << '/'
					<< std::setprecision(1) << std::fixed << std::setw(6) << c_total << total_units << " ("
					<< std::setprecision(1) << std::fixed << std::setw(5) << (100.0 * progress / total) << "%)\r";
			}
		}

		// clear the line
		if (log) *log << "                             \r";
	}
	// if we receive an error
	catch (...)
	{
		// clean up (because C++ doesn't have a "finally block" concept, duplicate code is the only way to preserve exception typing)
		clean;

		// throw whatever error we got
		throw;
	}

	// clean up
	clean;

	#undef clean
}

bool cryptf(const char *in_path, const char *out_path, const char *key, crypto_t crypto, std::ostream *log)
{
	// open input
	std::ifstream in(in_path, std::ios::binary);
	if (!in.is_open())
	{
		if (log) *log << "FAILURE: failed to open file \"" << in_path << "\" for reading\n";
		return false;
	}

	// make sure we're not going to save over the input
	// fs::equivalent() can throw if either path doesn't exist, so we need to check out_path before calling it
	if (fs::exists(out_path) && fs::equivalent(in_path, out_path))
	{
		if (log) *log << "FAILURE: attempt to save over input: \"" << in_path << "\" -> \"" << out_path << "\"\n";
		return false;
	}

	// open output
	std::ofstream out(out_path, std::ios::trunc | std::ios::binary);
	if (!out.is_open())
	{
		if (log) *log << "FAILURE: failed to open file \"" << out_path << "\" for writing\n";
		return false;
	}

	// print header
	if (log) *log << "processing \"" << in_path << "\" -> \"" << out_path << "\"\n";

	// hand off to stream function
	crypt(in, out, key, crypto, log);

	// success
	return true;
}
bool cryptf(const char *path, const char *key, crypto_t crypto, std::ostream *log)
{
	// open the file
	std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);

	// make sure we opened the file
	if (!f.is_open())
	{
		if (log) *log << "FAILURE: failed to open file \"" << path << "\" for reading and writing\n";
		return false;
	}

	// print header
	if(log) *log << "processing \"" << path << "\"\n";

	// hand off to stream function
	crypt(f, f, key, crypto, log);

	// success
	return true;
}
int cryptf_recursive(const char *root_path, const char *key, crypto_t crypto, std::ostream *log)
{
	int successes = 0; // number of successful operations

	// for each item recursively
	for (const fs::directory_entry &entry : fs::recursive_directory_iterator(root_path))
	{
		// if this is a file (current compiler aparently doesn't define the member func versions, so use the function versions)
		if (fs::is_regular_file(entry.status()))
		{
			// hand off to cryptf
			if (cryptf(entry.path().generic_string().c_str(), key, crypto, log)) ++successes;
		}
	}

	return successes;
}
