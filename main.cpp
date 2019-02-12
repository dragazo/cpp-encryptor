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

/*
#ifdef _DEBUG
// runs diagnostics on the supplied string key
void diag(const char *key)
{
	int maskc;
	std::unique_ptr<int[]> masks = getmasks(key, maskc);

	std::cout << key << " ->\n";
	for (int m = 0; m < maskc; ++m)
	{
		for (int i = 0; i < 8; ++i) std::cout << std::setw(3) << masks[m * 8 + i] << ' ';
		std::cout << '\n';
	}
	std::cout << '\n';
}
#endif
*/

int main(int argc, const char **argv)
{
	#define __help { print_help(std::cout); return 0; }
	#define __crypto(c) { if (has_mode) { std::cerr << "cannot respecify mode\n"; return 0; } has_mode = true; mode = crypto_service::mode::c; }
	#define __password { if (password) { std::cerr << "cannot respecify password\n"; return 0; } if (i + 1 >= argc) { std::cerr << "option " << argv[i] << " expected a password to follow\n"; return 0; } password = argv[++i]; }
	#define __recursive { recursive = true; }
	#define __time { time = true; }

	// -- parse terminal args -- //

	bool                           recursive = false;  // flags that we're batch processing the files
	bool                           time = false;       // flags that we're batch processing the files
	const char                    *password = nullptr; // password to use
	bool                           has_mode = false;   // marks if mode is valid
	crypto_service::mode           mode = crypto_service::mode::encrypt; // crypto mode to use
	std::vector<const char*>       paths;              // the provided paths
	
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
	if (!has_mode) { std::cerr << "expected -e or -d. see -h for help\n"; return 0; }
	if (!password) { std::cerr << "expected -p. see -h for help\n"; return 0; };

	// generate the worker with the proper password and mode
	crypto_service crypto(password, mode);

	// create a buffer
	std::unique_ptr<char[]> buffer = std::make_unique<char[]>(buffer_size);

	// begin timing
	auto start = std::chrono::high_resolution_clock::now();
	
	// if recursive processing
	if (recursive)
	{
		// process each pathspec recursively
		for (std::size_t i = 0; i < paths.size(); ++i) crypto.process_file_in_place_recursive(paths[i], buffer.get(), buffer_size, &std::cout);
	}
	// otherwise doing from-to copy
	else
	{
		// ensure there were exactly 2 paths specified
		if (paths.size() != 2) { std::cerr << "non-recursive mode requires exactly 2 paths (input and output). see -h for help\n"; return 0; }

		// process the file
		crypto.process_file(paths[0], paths[1], buffer.get(), buffer_size, &std::cout);
	}

	// display elapsed time if timing flag set
	if (time)
	{
		auto t = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start).count();
		std::cout << "elapsed time: " << t << "ms\n";
	}

	// no errors
	return 0;
}
