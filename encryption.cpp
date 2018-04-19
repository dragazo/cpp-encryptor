#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <thread>
#include "encryption.h"
#include "filesize.h"

// the size of the buffer used during encryption
constexpr int buffer_size = 1000000;

// ensure that the the buffer size isn't stupid
static_assert(buffer_size < std::numeric_limits<int>::max(), "buffer index uses int. cannot exceed int maximum.");

// a series of pre-loaded factorials
constexpr int F[]{1, 2, 6, 24, 120, 720, 5040};
// a series of pre-loaded powers of 2
constexpr int P[]{1, 2, 4, 8, 16, 32, 64, 128};

// -------------------------------

int* getmasks(int key)
{
	// create a list of powers of 2 (represents the bit mask phase shifts for each bit in a byte)
	std::vector<int> pos = {1, 2, 4, 8, 16, 32, 64, 128};
	int *r = new int[8]; // allocate the result
	key %= 40320;        // there are only 8! possibilities, so ensure key is in that range

	// get all 8 bitmasks
	for (int i = 0; i < 7; ++i)
	{
		int res = key / F[6 - i];     // get the index of the bitmask
		r[i] = pos[res];              // save it
		pos.erase(pos.begin() + res); // remove it from the list
		key -= res * F[6 - i];        // reduce key to put it in range for the next pass
	}
	r[7] = pos[0];

	// return resulting masks
	return r;
}
void freemasks(int *masks)
{
	// free the masks
	delete[] masks;
}

int** getmasks(const char *key, int &maskc)
{
	// simple implementation: one set for each character in the string

	maskc = strlen(key); // get te string length
	int **k = new int*[maskc]; // allocate the result

	// get the bitmask set for each character
	for (int i = 0; i < maskc; ++i) k[i] = getmasks(key[i]);

	return k;
}
void freemasks(int **masks, int maskc)
{
	// free each mask set
	for (int i = 0; i < maskc; ++i) delete[] masks[i];
	// free the overall array
	delete[] masks;
}

// -------------------------------

void encrypt(char *data, int **masks, int maskc, int offset, int length, int maskoffset)
{
#define bitop(i) if ((set[i] & ch) != 0) res += P[i]

	int res;  // the result of one iteration
	int *set; // the mask set to use
	int ch;   // the character being processed

	// for each byte up to len
	for (int i = 0; i < length; ++i)
	{
		res = 0;                               // zero the result
		set = masks[(i + maskoffset) % maskc]; // get the mask set to use
		ch = data[i + offset];                 // get the character being processed

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
		data[i + offset] = res;
	}

#undef bitop
}
void decrypt(char *data, int **masks, int maskc, int offset, int length, int maskoffset)
{
#define bitop(i) if ((P[i] & ch) != 0) res += set[i]

	int res;  // the result of one iteration
	int *set; // the mask set to use
	int ch;   // the character to process

	// for each byte up to len
	for (int i = 0; i < length; ++i)
	{
		res = 0;                               // zero the result
		set = masks[(i + maskoffset) % maskc]; // get the mask set to use
		ch = data[i + offset];                 // get the character being processed

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
		data[i + offset] = res;
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

void cryptf(std::istream &in, std::ostream &out, const char *key, crypto_t processor, std::ostream *log)
{
	// macro used for cleaning up after execution
#define clean {/* set running to false and wait for threads to terminate */\
	running = false; for (int i = 0; i < threadc; ++i) threads[i].join();\
	delete[] threads; delete[] settings;\
	for (int i(0); i < maskc; ++i) delete[] masks[i]; delete[] masks;\
	delete[] buffer;\
	}

	// -- initialize data -- //

	// the exception generated during execution
	std::exception *except = nullptr;

	// the number of bytes that have been processed
	std::streamsize progress = 0;

	// allocate the data buffer
	char *buffer = new char[buffer_size];

	// turn the key into masks
	int maskc;
	int **masks = getmasks(key, maskc);

	// get the number of threads to create (full processor utilization)
	int threadc = std::thread::hardware_concurrency() - 1;
	// if for whatever reason that's negative, set it to zero
	if (threadc < 0) threadc = 0;

	// allocate the threads and settings
	std::thread *threads = threadc > 0 ? new std::thread[threadc] : nullptr;
	CryptoSettings *settings = threadc > 0 ? new CryptoSettings[threadc] : nullptr;

	// flag that marks that execution is going on
	bool running = true;

	// initialize the threads and settings
	for (int i = 0; i < threadc; ++i)
	{
		// initialize the thread object
		threads[i] = (std::thread)([processor, buffer, masks, maskc, &settings = settings[i], &running]()
		{
			// if we're still running
			while (running)
			{
				// if we have stuff to do
				if (settings.has_data)
				{
					// process the data
					processor(buffer, masks, maskc, settings.start, settings.width, settings.maskoffset);
					// mark that we did it
					settings.has_data = false;
				}

				// might as well end our time slice (otherwise would just be a spin wait)
				std::this_thread::yield();
			}
		});

		// initialize the settings object
		settings[i].has_data = false;
	}

	// -- and the fun begins -- //

	try
	{
		// loop over the mask offset (each pass consumes buffer_size, so increment by that)
		for (int offset = 0; ; offset = (offset + buffer_size) % maskc)
		{
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
			processor(buffer, masks, maskc, width * threadc, len - width * threadc, (offset + width * threadc) % maskc);

			// if we gave the threads work, wait for them to finish
			if (width > 0) for (int i(0); i < threadc; ++i)
				while (settings[i].has_data) std::this_thread::yield();

			// write the result back to output
			out.write(buffer, len);
			// increase progress by number of bytes read
			progress += len;

			// if logging enabled
			if (log)
			{
				// compact the progress size
				const char *progress_units;
				double c_progress = compact_filesize((double)progress, progress_units);

				// output progress
				*log << "processed " << std::setprecision(1) << std::fixed << c_progress << progress_units << '\n';
			}
		}

		// if logging enabled
		if (log)
		{
			// output completion message
			*log << "operation completed\n";
		}
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