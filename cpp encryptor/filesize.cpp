#include <iostream>
#include "filesize.h"

double compact_filesize(double bytes, const char *&units)
{
	static const double conversion_mult = 1024;
	static const char *unit_list[] = {"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

	if (bytes <= 1)
	{
		units = unit_list[0];
		return bytes;
	}

	int index(log(bytes) / log(conversion_mult));

	if (index > 8) index = 8;
	units = unit_list[index];

	return bytes / pow(conversion_mult, index);
}