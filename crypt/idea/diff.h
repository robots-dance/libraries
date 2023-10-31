#ifndef __DIFF_H__
#define __DIFF_H__

#include <stdio.h>

#define PRINT_DATA(data, len) do { \
	for (int i = 0; i < len; i++) \
		printf("%02x ", data[i]); \
	printf("\n"); \
} while(0);

unsigned char getFigureAmount(unsigned long number);
int randEx(int min, int max);
void randInit();

#endif