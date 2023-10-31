#include <stdlib.h>
#include "iutils.h"

byte *read_file_data(FILE *file, BUFF_INT *fsize)
{
	byte *result;
	fseek(file, 0, SEEK_END);
	BUFF_INT fileSize = ftell(file);
	fseek(file, 0, 0);
	result = malloc(idea_get_ctext_size(fileSize));
	BUFF_INT i = 0;
	while (i < fileSize)
	{
		result[i] = fgetc(file);
		i++;
	}
	*fsize = fileSize;
	return result;
}

void write_file_data(FILE *file, byte *data, BUFF_INT size)
{
	for (BUFF_INT i = 0; i < size; i++)
		fputc(data[i], file);
}

byte *readFile(const char *path, BUFF_INT *fsize, byte *error)
{
	byte *result = NULL;
	FILE *inp = fopen(path, "r");
	if (inp)
	{
		result = read_file_data(inp, fsize);
		fclose(inp);
	}
	else if (error)
		*error = 1;
	return result;
}
