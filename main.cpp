#include <iostream>
#include <chrono>
#include "encryption.h"

// outputs the help message
void print_help(std::ostream &ostr)
{
	
	ostr << "usage: (-h / --help) (-e / --encrypt / -d / --decrypt) (password)\n";

}

int main(int argc, const char **argv)
{
	using namespace std::chrono;

	std::ostream &log = std::cerr; // stream to use for logging

	// --------------------------------------------

	const char *password = nullptr; // password to use
	crypto_t crypto = nullptr;      // crypto function to use

	// for each argument
	for (int i = 1; i < argc; ++i)
	{
		#define usage_err { log << "usage error - see -h for help\n"; return 0; }

		// -h or --help displays help
		if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0) { print_help(log);	return 0; }

		// -e or --encrypt specifies decrypt
		else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--encrypt") == 0) { usage_err; crypto = encrypt; }
		// -d or --decrypt specifies decrypt
		else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--decrypt") == 0) { usage_err; crypto = encrypt; }

		// otherwise it's the password
		else { usage_err; password = argv[i]; }

		#undef usage_err
	}

	// ensure we got all we needed
	if (!crypto) { log << "must specify an encryption mode\n"; return 0; }
	if (!password) { log << "must specify a password\n"; return 0; }

	// --------------------------------------

	try
	{
		// start the clock
		high_resolution_clock clock;
		auto start = clock.now();

		// do the thing
		cryptf(std::cin, std::cout, password, crypto, &log);

		// stop the clock
		auto stop = clock.now();
		milliseconds time = duration_cast<milliseconds>(stop - start);

		// display how long it took
		log << "elapsed time: " << time.count() << "ms\n";

		// no errors
		return 0;
	}
	// if any exceptions occur, 
	catch (const std::exception &ex)
	{
		// print it to stderr
		log << ex.what() << '\n';

		// return bad things
		return 1;
	}
}