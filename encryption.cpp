#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <filesystem>
#include <atomic>
#include <mutex>
#include <condition_variable>

#include "encryption.h"
#include "filesize.h"

namespace fs = std::filesystem;

// rotates an 8-bit value v to the right by n bits
#define rot_8(v, n) ((v >> n) | (v << n) & 0xff)

// pre-loaded factorials
constexpr int F[]{1, 1, 2, 6, 24, 120, 720, 5040};

// -------------------------------

// gets the masks for an individual key (sub array of 8)
void getmasks(int key, int *dest)
{
	// create a list of powers of 2 (represents the bit mask phase shifts for each bit in a byte)
	std::vector<int> pos = { 1, 2, 4, 8, 16, 32, 64, 128 };
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

crypto_service::mask_set::mask_set(const char *key)
{
	// compute the mask count - null or empty string is illegal - throw
	std::size_t maskc = key ? std::strlen(key) : 0;  // get the string length
	if (maskc == 0) throw std::invalid_argument("key string was null or empty");

	// resize the vector to the proper size
	masks.resize(maskc * 8);

	// for each set of 8 masks
	for (std::size_t i = 0; i < maskc; ++i)
	{
		// get the raw key and next raw key
		int _key = key[i];
		int _next = key[(i + 1) % maskc];

		// interlace it with the next raw key
		_key ^= rot_8(_next, 4);

		// multiply to extend interval
		_key *= (key[i] ^ _key ^ _next) * 21143; // the literal is drawn from a large prime number to help evenly distribute resultant keys

		// get the masks for the interlaced key
		getmasks(_key, masks.data() + (i * 8));
	}
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

crypto_service::crypto_service(const char *key, mode m) : masks(key)
{
	// masks was already set - set mode now cause it might also throw
	setmode(m);

	// get the number of workers to create - 1 per processor with a minimum of 1 if that's zero for some reason (better safe than sorry)
	workerc = std::max(std::thread::hardware_concurrency(), 1u);

	// allocate the threads and settings
	workers = std::make_unique<worker_thread_t[]>(workerc);

	{
		std::unique_lock<std::mutex> sync_lock(sync_mutex);

		workers_alive = true;  // mark workers as being alive but we're not ready for them to do anything just yet - done under lock to prevent reordering problems for shared memory
		workers_dirty = false; // mark that they're not dirty - they'll immediately get up-to-date copies upon starting
		workers_done = 0;      // make sure to reset the done count - done by us because it's our spurious failure condition

		// start the worker threads - done under lock to ensure all workers are waiting before we continue
		for (std::size_t i = 0; i < workerc; ++i)
		{
			workers[i].ready = false; // mark as not ready (nothing to do yet)

			workers[i].thread = std::thread([this, i]()
			{
				// create the unique lock now so we don't have to inside the loop
				std::unique_lock<std::mutex> sync_lock(sync_mutex, std::defer_lock);

				while (true)
				{
					// take the sync mutex and wait on the worker cv before we begin
					sync_lock.lock();
					if (++workers_done == workerc) main_cv.notify_one(); // if we're the last to wait, notify main before we wait for work
					worker_cv.wait(sync_lock, [this, i] { return workers[i].ready; });
					sync_lock.unlock();

					// at this point we've been woken up and the ready flag is set - we're ready to do something.
					// first and foremost, if alive is false the requested action is to terminate.
					if (!workers_alive) return;

					// clear the ready flag so we won't spuriously wake up on the next wait and try to do something
					workers[i].ready = false;

					// -- otherwise process our data -- //

					// otherwise process our piece of the data array
					crypto_func(data, masks.get(), masks.count(), width * i,
						i == workerc - 1 ? length - width * i : width, // last index worker does whatever's left over of the array
						(maskoff + width * i) % masks.count());
				}
			});
		}
		main_cv.wait(sync_lock, [this] {return workers_done == workerc; });
	}
}
crypto_service::~crypto_service()
{
	// request worker thread - done under lock to prevent case of alive/ready write operations being reordered
	// i.e. without the mutex nothing stops the alive write from being invisible to the worker threads
	std::unique_lock<std::mutex> sync_lock(sync_mutex);
	workers_alive = false;
	for (std::size_t i = 0; i < workerc; ++i) workers[i].ready = true; // mark all as ready
	worker_cv.notify_all();
	sync_lock.unlock();
	
	// join the workers
	for (std::size_t i = 0; i < workerc; ++i) workers[i].thread.join();
}

void crypto_service::setmode(mode m)
{
	// update crypto func
	switch (m)
	{
	case mode::encrypt: crypto_func = encrypt; break;
	case mode::decrypt: crypto_func = decrypt; break;

	default: throw std::invalid_argument("unknown crypto mode specified");
	}

	reset(); // different key implies we're beginning unrelated data - reset
}
void crypto_service::setkey(const char *key)
{
	// update masks
	masks = mask_set(key);

	reset(); // different key implies we're beginning unrelated data - reset
}

void crypto_service::reset() noexcept
{
	maskoff = 0;
}
void crypto_service::process(char *buffer, int start, int count)
{
	// update the shared variables
	data = buffer + start;
	length = count;
	width = count / workerc;
	
	// make sure to reset the workers done count for them before they wake up - done by us because it's our spurious wakeup condition
	workers_done = 0;

	{
		// wake up workers and wait for them to all be done
		std::unique_lock<std::mutex> sync_lock(sync_mutex);
		for (std::size_t i = 0; i < workerc; ++i) workers[i].ready = true; // mark all as ready
		worker_cv.notify_all();
		main_cv.wait(sync_lock, [this] { return workers_done == workerc; });
	}

	// bump up offset
	maskoff = (maskoff + count) % masks.count();
}

// -------------------------------

void crypto_service::process_stream(std::istream &in, std::ostream &out, char *buffer, int buflen, std::ostream *log)
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
	reset();

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
		process(buffer, 0, (int)len);

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

bool crypto_service::process_file(const char *in_path, const char *out_path, char *buffer, int buflen, std::ostream *log)
{
	// open the files
	std::ifstream in;
	std::ofstream out;
	if (!openf(in_path, out_path, in, out, log)) return false;

	// hand off to stream function
	process_stream(in, out, buffer, buflen, log);
	return true;
}
bool crypto_service::process_file_in_place(const char *path, char *buffer, int buflen, std::ostream *log)
{
	// open the file
	std::fstream f;
	if (!openf(path, f, log)) return false;

	// hand off to stream function
	process_stream(f, f, buffer, buflen, log);
	return true;
}

int crypto_service::process_file_in_place_recursive(const char *root_path, char *buffer, int buflen, std::ostream *log)
{
	int successes = 0; // number of successful operations

	// if it's a file, process it
	if (fs::is_regular_file(root_path))
	{
		if (process_file_in_place(root_path, buffer, buflen, log)) ++successes;
	}
	// if it's a directory, process contents recursively
	else if (fs::is_directory(root_path))
	{
		// for each item recursively
		for (const fs::directory_entry &entry : fs::recursive_directory_iterator(root_path))
		{
			// if this is a file - hand off to cryptf
			if (fs::is_regular_file(entry.status()))
			{
				if (process_file_in_place(entry.path().generic_string().c_str(), buffer, buflen, log)) ++successes;
			}
		}
	}

	return successes;
}
