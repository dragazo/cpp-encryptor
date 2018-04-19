#include <iostream>
#include "filesize.h"

double compact_filesize(double bytes, const char *&units)
{
	// the number of bytes in a KB
	static const double conversion_mult = 1024;
	// static container for the suffixes
	static const char *unit_list[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

	// account for degenerate case of 
	if (bytes <= 1)
	{
		units = unit_list[0];
		return bytes;
	}

	// get the index of the correct suffix
	int index = (int)(std::log(bytes) / std::log(conversion_mult));
	// but we can't go past suffix index 8 (we'll probably die as a species long before this is a problem)
	if (index > 8) index = 8;

	// set the suffix
	units = unit_list[index];
	// return the compacted file size
	return bytes / std::pow(conversion_mult, index);
}