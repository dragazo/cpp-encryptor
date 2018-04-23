#include <iostream>
#include <chrono>
#include <fstream>
#include <vector>
#include <iomanip>
#include "encryption.h"

// outputs the help message
void print_help(std::ostream &ostr)
{
	ostr << '\n';

	ostr << "usage: cpp_encryptor [<options>] [--] <pathspec>...\n\n";

	ostr << "    -h, --help                    shows this help message\n";
	ostr << "    -e, --encrypt                 specifies that files should be encrypted\n";
	ostr << "    -d, --decrypt                 specifies that files should be decrypted\n";
	ostr << "    -p, --password <password>     specifies the password to use\n";
	ostr << "    -b, --batch                   specifies that each file should be processed in-place.\n";
	ostr << "                                  if not present, <pathspec> must contain exactly 2 files (in and out)\n";

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
	#define usage_err { std::cout << "usage error - see -h for help\n"; return 0; }

	#define __help { print_help(std::cout); return 0; }
	#define __crypto(c) { if(crypto) usage_err; crypto = (c); }
	#define __password { if(password) usage_err; if (i + 1 >= argc) { std::cout << "option " << argv[i] << " expected a password to follow\n"; return 0; } password = argv[++i]; }
	#define __batch { batch = true; }

	// -- parse terminal args -- //

	std::ostream            *log = &std::cout;   // stream to use for logging
	bool                     batch = false;      // flags that we're batch processing the files
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
		else if (strcmp(argv[i], "--password") == 0) __password
		else if (strcmp(argv[i], "--batch") == 0) __batch
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
				case 'b': __batch; break;

				// otherwise flag was unknown
				default: std::cout << "unknown option '" << *pos << "'\n"; usage_err;
				}
			}
		}
		// otherwise it's a file path
		else paths.push_back(argv[i]);
	}

	// ensure we got a mode and password
	if (!crypto || !password) usage_err;

	// if batch processing
	if (batch)
	{
		// process each file in-place
		for (int i = 0; i < paths.size(); ++i) cryptf(paths[i], password, crypto, log);
	}
	// otherwise doing from-to copy
	else
	{
		// ensure there were exactly 2 paths specified
		if (paths.size() != 2) usage_err;

		// process the file
		cryptf(paths[0], paths[1], password, crypto, log);
	}

	// no errors
	return 0;
}