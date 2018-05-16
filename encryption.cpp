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

// pre-loaded factorials
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

ParallelCrypto::ParallelCrypto()
{
	// flag as active state
	active = true;

	// get the number of threads to create (#processors that aren't us) (make sure it's not negative for some reason)
	threadc = std::max(std::thread::hardware_concurrency() - 1, 0u);

	// allocate the threads and settings
	threads = threadc > 0 ? new std::thread[threadc] : nullptr;
	has_data = threadc > 0 ? new bool[threadc] : nullptr;

	// initialize the threads and settings
	for (int i = 0; i < threadc; ++i)
	{
		// initialize the settings object
		has_data[i] = false;

		// initialize the thread object
		threads[i] = (std::thread)([this, i]()
		{
			// if we're still running
			while (active)
			{
				// if we have stuff to do
				if (has_data[i])
				{
					// process the data
					crypto(data, masks, maskc, width * i, width, (maskoff + width * i) % maskc);
					// mark that we did it
					has_data[i] = false;
				}

				// might as well end our time slice (otherwise would just be a spin wait)
				std::this_thread::yield();
			}
		});
	}

	// null user-provided settings (safety)
	crypto = nullptr;
	masks = nullptr;
	maskc = 0;
	maskoff = 0;
}
ParallelCrypto::~ParallelCrypto()
{
	// request thread stop
	active = false;

	// join workers
	for (int i = 0; i < threadc; ++i) threads[i].join();
	
	// free private resources
	delete[] threads;
	delete[] has_data;

	// null them to ensure destroying multiple times is safe
	threads = nullptr;
	has_data = nullptr;

	// zero thread count
	threadc = 0;
}

void ParallelCrypto::process(char *buffer, int start, int count)
{
	// account for start index
	buffer += start;

	// store data data
	data = buffer;
	width = count / (threadc + 1); // threadc + 1 because we'll be doing a slice

	// if width is positive, distribute work load to the threads
	if (width > 0) for (int i = 0; i < threadc; ++i) has_data[i] = true;

	// we do the last slice ourselves
	crypto(data, masks, maskc, width * threadc, count - width * threadc, (maskoff + width * threadc) % maskc);

	// wait for the threads to finish
	for (int i = 0; i < threadc; ++i) while (has_data[i]) std::this_thread::yield();

	// bump up offset
	maskoff = (maskoff + count) % maskc;
}

// -------------------------------

void crypt(std::istream &in, std::ostream &out, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log)
{
	// -- load stats -- //

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

	// -- and the fun begins -- //

	// reset mask offset
	worker.maskoff = 0;

	while (true)
	{
		// seek read pos (required if in/out are the same file)
		in.seekg(in_pos);
		// read data from input
		in.read(buffer, buflen);

		// get the number of bytes read
		std::streamsize len = in.gcount();
		// if we read nothing, we're done
		if (len == 0) break;

		// process the data
		worker.process(buffer, 0, (int)len);

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

// opens the files and displays a success/error message. returns true on success
bool openf(const char *in_path, const char *out_path, std::ifstream &in, std::ofstream &out, std::ostream *log = nullptr)
{
	// open input
	in = std::ifstream(in_path, std::ios::binary);
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
	out = std::ofstream(out_path, std::ios::trunc | std::ios::binary);
	if (!out.is_open())
	{
		if (log) *log << "FAILURE: failed to open file \"" << out_path << "\" for writing\n";
		return false;
	}

	// print success header (for file processing)
	if (log) *log << "processing \"" << in_path << "\" -> \"" << out_path << "\"\n";

	// success
	return true;
}
bool openf(const char *path, std::fstream &f, std::ostream *log = nullptr)
{
	// open the file
	f = std::fstream(path, std::ios::in | std::ios::out | std::ios::binary);

	// make sure we opened the file
	if (!f.is_open())
	{
		if (log) *log << "FAILURE: failed to open file \"" << path << "\" for reading and writing\n";
		return false;
	}

	// print success header (for file processing)
	if (log) *log << "processing \"" << path << "\"\n";

	// success
	return true;
}

bool cryptf(const char *in_path, const char *out_path, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log)
{
	// open the files
	std::ifstream in;
	std::ofstream out;
	if (!openf(in_path, out_path, in, out, log)) return false;

	// hand off to stream function
	crypt(in, out, worker, buffer, buflen, log);
	return true;
}
bool cryptf(const char *path, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log)
{
	// open the file
	std::fstream f;
	if (!openf(path, f, log)) return false;

	// hand off to stream function
	crypt(f, f, worker, buffer, buflen, log);
	return true;
}

int cryptf_recursive(const char *root_path, ParallelCrypto &worker, char *buffer, int buflen, std::ostream *log)
{
	int successes = 0; // number of successful operations

	// if it's a file, process it
	if (fs::is_regular_file(root_path))
	{
		
		if (cryptf(root_path, worker, buffer, buflen, log)) ++successes;
	}
	// if it's a directory, process contents recursively
	else if (fs::is_directory(root_path))
	{
		// for each item recursively
		for (const fs::directory_entry &entry : fs::recursive_directory_iterator(root_path))
		{
			// if this is a file 
			if (fs::is_regular_file(entry.status()))
			{
				// hand off to cryptf
				if (cryptf(entry.path().generic_string().c_str(), worker, buffer, buflen, log)) ++successes;
			}
		}
	}

	return successes;
}
