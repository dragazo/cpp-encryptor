#ifndef FILESIZE_H
#define FILESIZE_H

// compresses the file size in bytes into a more human-friendly format (GB, MB, etc.)
double compact_filesize(double bytes, const char *&units);

#endif
