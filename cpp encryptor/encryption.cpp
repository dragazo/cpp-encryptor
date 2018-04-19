#include <vector>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <thread>
#include "encryption.h"
#include "filesize.h"

constexpr int buffer_size = 1000000;

static_assert(buffer_size < std::numeric_limits<fint>::max(), "buffer index uses fint. cannot exceed fint capacity.");

constexpr fint
F[]{1, 2, 6, 24, 120, 720, 5040},
P[]{1, 2, 4, 8, 16, 32, 64, 128};

fint* getmasks(fint key)
{
	std::vector<fint> pos = {1, 2, 4, 8, 16, 32, 64, 128};
	fint *r = new fint[8];
	key %= 40320;

	for (int i = 0; i < 7; ++i)
	{
		fint res = key / F[6 - i];
		r[i] = pos[res];
		pos.erase(pos.begin() + res);
		key -= res * F[6 - i];
	}
	r[7] = pos[0];

	return r;
}
fint** getmasks(const char *keys, fint &maskc)
{
	maskc = strlen(keys);
	fint **k = new fint*[maskc];
	for (fint i = 0; i < maskc; ++i) k[i] = getmasks(keys[i]);

	return k;
}

void encrypt(char *data, fint **masks, fint maskc, fint offset, fint length, fint maskoffset)
{
#define bitop(i) if ((set[i] & d) != 0) res += P[i]

	fint res;  // the result of one iteration
	fint *set; // the mask set to use
	char d;    // the character to process

	// iterate through each character in data
	for (int i = 0; i < length; ++i)
	{
		res = 0;
		set = masks[(i + maskoffset) % maskc];
		d = data[i + offset];

		// macro inlining (potentially faster, depending on optimizer)
		bitop(0);
		bitop(1);
		bitop(2);
		bitop(3);
		bitop(4);
		bitop(5);
		bitop(6);
		bitop(7);

		// loop version
		//for (fint m = 0; m < 8; ++m)
			//if ((set[m] & d) != 0) res += P[m];

		data[i + offset] = res;
	}

#undef bitop
}
void decrypt(char *data, fint **masks, fint maskc, fint offset, fint length, fint maskoffset)
{
#define bitop(i) if ((P[i] & d) != 0) res += set[i]

	fint res;  // the result of one iteration
	fint *set; // the mask set to use
	char d;    // the character to process

	for (int i = 0; i < length; ++i)
	{
		res = 0;
		set = masks[(i + maskoffset) % maskc];
		d = data[i + offset];

		// macro inlining (potentially faster, depending on optimizer)
		bitop(0);
		bitop(1);
		bitop(2);
		bitop(3);
		bitop(4);
		bitop(5);
		bitop(6);
		bitop(7);

		// loop version
		//for (fint m = 0; m < 8; ++m)
			//if ((P[m] & d) != 0) res += set[m];

		data[i + offset] = res;
	}

#undef bitop
}

static struct ProcessorSettings
{
	bool has_data = false;
	std::streamsize start = 0, width = 0;
	fint maskoffset = 0;
};

void encrypt_decrypt(const char *in_path, const char *out_path, const char *key, processor_t processor)
{
#define clean {/* set running to false and wait for threads to terminate */\
	running = false;\
	for (fint i = 0; i < threadc; ++i) threads[i].join();\
	/* delete settings and thread */\
	delete[] settings;\
	delete[] threads;\
	/* delete masks */\
	for (fint i(0); i < maskc; ++i) delete[] masks[i];\
	delete[] masks;\
	/* delete the data buffer */\
	delete[] buffer;\
	}

	std::ifstream in(in_path, std::ios::binary | std::ios::ate);
	if (!in.is_open()) throw static_cast<std::invalid_argument>("couldn't open specified input file");

	std::ofstream out(out_path, std::ios::binary);
	if (!out.is_open()) throw static_cast<std::invalid_argument>("couldn't open specified output file");

	std::streamsize length = in.tellg(), progress = 0;
	in.seekg(0);

	char *buffer = new char[buffer_size];

	fint maskc;
	fint **masks = getmasks(key, maskc);

	fint threadc = std::thread::hardware_concurrency() - 1;
	if (threadc < 0) threadc = 0;

	std::thread *threads = threadc > 0 ? new std::thread[threadc] : nullptr;
	ProcessorSettings *settings = threadc > 0 ? new ProcessorSettings[threadc] : nullptr;

	bool running = true;

	for (fint i = 0; i < threadc; ++i)
		threads[i] = static_cast<std::thread>([processor, buffer, masks, maskc, &settings = settings[i], &running] ()
		{
			while (running)
			{
				if (settings.has_data)
				{
					processor(buffer, masks, maskc, (fint)settings.start, (fint)settings.width, settings.maskoffset);
					settings.has_data = false;
				}

				std::this_thread::yield();
			}
		});

	try
	{
		for (fint offset = 0; ; offset = (offset + buffer_size) % maskc)
		{
			// read data from in
			in.read(buffer, buffer_size);
			std::streamsize len = in.gcount();
			// if we read nothing, we're done
			if (len == 0) break;

			// get width of each slice for a thread
			std::streamsize width = len / (threadc + 1);
			// if width is positive, distribute work load to the threads
			if (width > 0) for (fint i = 0; i < threadc; ++i)
			{
				settings[i].start = width * i;
				settings[i].width = width;
				settings[i].maskoffset = (offset + width * i) % maskc;

				settings[i].has_data = true;
			}

			// we do the last slice ourselves
			processor(buffer, masks, maskc, width * threadc, len - width * threadc, (offset + width * threadc) % maskc);
			
			// if we gave the threads work, wait for them to finish
			if (width > 0) for (fint i(0); i < threadc; ++i)
				while (settings[i].has_data) std::this_thread::yield();

			// write the result back to output
			out.write(buffer, len);

			// increase progress by number of bytes read
			progress += len;

			// output file size progress in compressed format to stdout
			const char *length_units, *progress_units;
			double c_length = compact_filesize((double)length, length_units), c_progress = compact_filesize((double)progress, progress_units);

			std::cout
				<< "progress: "
				<< std::setprecision(1) << std::fixed << c_progress << progress_units
				<< " / "
				<< std::setprecision(1) << std::fixed << c_length << length_units
				<< " ("
				<< std::setprecision(1) << std::fixed << (100.0 * progress / length)
				<< "%)\n";
		}

		// output completion
		std::cout << "operation completed\n";
	}
	// if we receive an error
	catch (...)
	{
		// clean up
		clean;

		// throw whatever error we got
		throw;
	}

	// clean up
	clean;
}
