#include <stdlib.h>
#include <time.h>
#include "diff.h"

unsigned char getFigureAmount(unsigned long number)
{
	unsigned char cntr = 0;
	while (number)
	{
		cntr++;
		number /= 10;
	}
	return cntr;
}

int randEx(int min, int max)
{
	/*
		генерирует целое число в диапазоне [min, max]
	*/
	if (max < min)
	{
		int tmp = min;
		min = max;
		max = tmp;
	}
	int range = max - min + 1;
	int result = min + (int)(range * (float)rand() / RAND_MAX);
	return result;
}

void randInit()
{
	// инициализирует генератор случайных чисел
	srand(time(0));
}

