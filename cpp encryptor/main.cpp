#include <iostream>
#include <chrono>
#include "encryption.h"

int main(int argc, char **args)
{
	using namespace std::chrono;

	try
	{
		if (argc != 5) throw static_cast<std::runtime_error>("invalid argument count - usage: (in_file) (out_file) (encrypt/decrypt) (password)");
		const char *in = args[1], *out = args[2], *mode = args[3], *key = args[4];
		
		processor_t processor;
		if (strcmp(mode, "encrypt") == 0) processor = encrypt;
		else if (strcmp(mode, "decrypt") == 0) processor = decrypt;
		else throw static_cast<std::runtime_error>("invalid process mode - usage: (in_file) (out_file) (encrypt/decrypt) (password)");

		high_resolution_clock clock;
		auto start = clock.now();

		encrypt_decrypt(in, out, key, processor);

		auto stop = clock.now();
		milliseconds time = duration_cast<milliseconds>(stop - start);

		std::cout << "elapsed time: " << time.count() << "ms\n";
	}
	catch (const std::exception &ex)
	{
		std::cout << ex.what() << '\n';
	}

	return 0;
}