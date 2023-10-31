#ifndef _IUTILS_H_
#define _IUTILS_H_

#include <stdio.h>
#include "idea.h"

// low-level funcs
byte *read_file_data(FILE *file, BUFF_INT *fsize);
void write_file_data(FILE *file, byte *data, BUFF_INT size);

// high-level funcs
byte *readFile(const char *path, BUFF_INT *fsize, byte *error);

#endif
