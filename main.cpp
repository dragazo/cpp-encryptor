#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <iomanip>
#include "encryption.h"

// size of buffer to create
constexpr int buffer_size = 1024 * 1024;

// outputs the help message
void print_help(std::ostream &ostr)
{
	ostr << '\n';
	
	ostr << "usage: cpp_encryptor [<options>] [--] <pathspec>...\n\n";

	ostr << "    -h, --help        shows this help message\n";
	ostr << "    -e, --encrypt     specifies that files should be encrypted\n";
	ostr << "    -d, --decrypt     specifies that files should be decrypted\n";
	ostr << "    -p <password>     specifies the password to use\n";
	ostr << "    -r                processes files/directories in-place recursively\n";
	ostr << "    -t                displays elapsed time after completion\n";

	ostr << '\n';
}

#ifdef _DEBUG
// runs diagnostics on the supplied string key
void diag(const char *key)
{
	int maskc;
	int *masks = getmasks(key, maskc);

	std::cout << key << " ->\n";
	for (int m = 0; m < maskc; ++m)
	{
		for (int i = 0; i < 8; ++i) std::cout << std::setw(3) << masks[m * 8 + i] << ' ';
		std::cout << '\n';
	}

	std::cout << '\n';

	delete[] masks;
}
#endif

int main(int argc, const char **argv)
{
	using namespace std::chrono;
	typedef high_resolution_clock hrc;

	#define __help { print_help(std::cout); return 0; }
	#define __crypto(c) { if(crypto) { std::cerr << "cannot respecify mode\n"; return 0; } crypto = (c); }
	#define __password { if(password) { std::cerr << "cannot respecify password\n"; return 0; } if (i + 1 >= argc) { std::cerr << "option " << argv[i] << " expected a password to follow\n"; return 0; } password = argv[++i]; }
	#define __recursive { recursive = true; }
	#define __time { time = true; }

	// -- parse terminal args -- //

	bool                     recursive = false;  // flags that we're batch processing the files
	bool                     time = false;       // flags that we're batch processing the files
	crypto_t                 crypto = nullptr;   // crypto function to use
	const char              *password = nullptr; // password to use
	std::vector<const char*> paths;              // the provided paths
	
	// for each argument
	for (int i = 1; i < argc; ++i)
	{
		// do the long names
		if (strcmp(argv[i], "--help") == 0) __help
		else if (strcmp(argv[i], "--encrypt") == 0) __crypto(encrypt)
		else if (strcmp(argv[i], "--decrypt") == 0) __crypto(decrypt)
		else if (strcmp(argv[i], "--") == 0); // no-op separator
		// do the short names
		else if (argv[i][0] == '-')
		{
			// for each 1-char flag (can string them together if desired)
			for (const char *pos = argv[i] + 1; *pos; ++pos)
			{
				// switch on the character
				switch (*pos)
				{
				case 'h': __help; break;
				case 'e': __crypto(encrypt); break;
				case 'd': __crypto(decrypt); break;
				case 'p': __password; break;
				case 'r': __recursive; break;
				case 't': __time; break;

				// otherwise flag was unknown
				default: std::cerr << "unknown option '" << *pos << "'. see -h for help\n"; return 0;
				}
			}
		}
		// otherwise it's a file path
		else paths.push_back(argv[i]);
	}

	// ensure we got a mode and password
	if (!crypto) { std::cerr << "expected -e or -d. see -h for help\n"; return 0; }
	if (!password) { std::cerr << "expected -p. see -h for help\n"; return 0; };

	// generate the worker
	ParallelCrypto worker;
	worker.crypto = crypto;
	worker.masks = getmasks(password, worker.maskc);
	
	// create a buffer
	char *buffer = new char[buffer_size];

	// begin timing
	hrc::time_point start = hrc::now();

	// if recursive processing
	if (recursive)
	{
		// process each pathspec each recursively
		for (unsigned int i = 0; i < paths.size(); ++i) cryptf_recursive(paths[i], worker, buffer, buffer_size, &std::cout);
	}
	// otherwise doing from-to copy
	else
	{
		// ensure there were exactly 2 paths specified
		if (paths.size() != 2) { std::cerr << "non-recursive mode requires exactly 2 paths (input and output). see -h for help\n"; return 0; }

		// process the file
		cryptf(paths[0], paths[1], worker, buffer, buffer_size, &std::cout);
	}

	// display elapsed time if timing flag set
	if (time)
	{
		long long t = duration_cast<std::chrono::milliseconds>(hrc::now() - start).count();
		std::cout << "elapsed time: " << t << "ms\n";
	}

	// free resources
	delete[] worker.masks;
	delete[] buffer;

	// no errors
	return 0;
}
