#include <stdio.h>
#include <stdlib.h>
#include "diff.h"
#include "idea.h"

#define CORRECT_WORD(value) (value ? value : 65536)
#define MUL(x, y) ( (unsigned long)(x * y) % 65537 )

BUFF_INT pow10(unsigned int n);


int evclid_ext(int b, int n)
{
	/*
		получает мультипликативную инверсию числа b в Zn
	*/
	int result;
	int r, t, q;
	int r1 = n, r2 = b, t1 = 0, t2 = 1;
	while (r2 > 0)
	{
		q = r1 / r2;
		
		r = r1 - q * r2;
		r1 = r2;
		r2 = r;
		
		t = t1 - q * t2;
		t1 = t2;
		t2 = t;
	}
	result = t1 % t;
	if (result < 0)
		result += n;
	return result;
	
}

byte *idea_crypt_data(byte *data, byte key[IDEA_KEY_SIZE], IWORD *keysShedule, BUFF_INT inpSize, bool normalizedMode, BUFF_INT *outSize, byte *outBuff, CryptOperationType type)
{
	byte *result = NULL;
	BUFF_INT blockAm = type == COEncrypt && normalizedMode ? idea_normalize_data(data, inpSize) : inpSize / IDEA_BLOCK_SIZE; 
	BUFF_INT resSize = blockAm * IDEA_BLOCK_SIZE;
	
	result = outBuff ? outBuff : malloc(resSize);
	
	IWORD *keys;
	if (!keysShedule)
		keys = idea_get_keys(key, type);
	else
		keys = keysShedule;
	
	// block 'crypting'
	IWORD buffer[10][4];
	BUFF_INT index = 0, oldIndex;
	int curD, curKey, K5, K6;
	IWORD tmp, tmp1, tmp2, word, A, B, C, D, E, F;
	IWORD outBlock[4];
	byte b1, b2;
	for (BUFF_INT i = 0; i < blockAm; i++)
	{
		// считываем 4 слова
		oldIndex = index;
		for (byte j = 0; j < 4; j++)
		{
			word = (IWORD)data[index] << 8 | data[index + 1];
			index += 2;
			buffer[0][j] = word;
		}
		
		for (byte j = 0; j < 8; j++)
		{
			byte base = j * 6;
			byte nextIndex = j + 1;
			
			curD = buffer[j][0];
			curD = CORRECT_WORD(curD);
			curKey = keys[base];
			curKey =CORRECT_WORD(curKey);
			A = MUL(curD, curKey); 
			//printf("[%05x, %05x, %04x] ", curD, curKey, A);
			
			curD = buffer[j][1];
			curD = CORRECT_WORD(curD);
			B = (curD + keys[base + 1]) % 65536;
			//printf("[%05x, %05x, %04x] ", curD, keys[base + 1], B);
			
			curD = buffer[j][2];
			curD = CORRECT_WORD(curD);
			C = (curD + keys[base + 2]) % 65536;
			//printf("[%05x, %05x, %04x] ", curD, keys[base + 2], C);
			
			curD = buffer[j][3];
			curD = CORRECT_WORD(curD);
			curKey = keys[base + 3];
			curKey = CORRECT_WORD(curKey);
			D = MUL(curD, curKey); 
			//printf("[%05x, %05x, %04x] ", curD, curKey, D);
			
			E = A ^ C;
			F = B ^ D;
			
			K5 = keys[base + 4];
			K5 = CORRECT_WORD(K5);
			K6 = keys[base + 5];
			K6 = CORRECT_WORD(K6);
			
			tmp1 = MUL(E, K5); 
			tmp2 = (F + tmp1) % 65536;
			tmp = MUL(tmp2, K6); 
			buffer[nextIndex][0] = A ^ tmp;
			buffer[nextIndex][1] = C ^ tmp;
			
			tmp = (MUL(E, K5) + tmp) % 65536;
			buffer[nextIndex][2] = B ^ tmp;
			buffer[nextIndex][3] = D ^ tmp;
		}
		
		curD = buffer[8][0];
		curD = CORRECT_WORD(curD);
		curKey = keys[48];
		curKey = CORRECT_WORD(curKey);
		outBlock[0] = MUL(curD, curKey);
		
		outBlock[1] = (buffer[8][2] + keys[49]) % 65536;
		outBlock[2] = (buffer[8][1] + keys[50]) % 65536;
		
		curD = buffer[8][3];
		curD = CORRECT_WORD(curD);
		curKey = keys[51];
		curKey = CORRECT_WORD(curKey);
		outBlock[3] = MUL(curD, curKey);
		
		for (byte j = 0; j < 4; j++)
		{
			word = outBlock[j];
			//printf("%04x ", word);
			b1 = (byte)(word & 0x00FF); // младший
			word >>= 8;
			b2 = (byte)word; // старший
			result[oldIndex] = b2;
			result[oldIndex + 1] = b1;
			oldIndex += 2;
		}
		//printf("\n");
	}
	// end block
	
	if (type == CODecrypt && normalizedMode)
	{
		// извлекаем длину из последних блоков
		BUFF_INT len = 0; 
		BUFF_INT start = (blockAm - 2) * IDEA_BLOCK_SIZE, i;
		byte end = 0, figureAm = 0;
		i = start;
		while (end != 0x63)
		{
			end = result[i];
			if (end != 0x63)
			{
				len += pow10(figureAm) * end;
				figureAm++;
				i++;
			}
		}
		resSize = len;
	}
	
	if (outSize)
		*outSize = resSize;
	if (!keysShedule)
		free(keys);
	return result;
}

void idea_dbg_print_keys(IWORD *keys)
{
	for (int i = 0; i < 8; i++)
	{
		for (int j = 0; j < 6; j++)
		{
			printf("%04x", keys[i * 6 + j]);
			if (j != 5)
				printf(" ");
		}
		printf("\n");
	}
	
	for (int i = 3; i >= 0; i--)
	{
		printf("%04x", keys[51 - i]);
		if (i != 0)
			printf(" ");
	}
	printf("\n");
}

IWORD *idea_get_keys(KEY_PTR key, CryptOperationType type)
{
	IWORD *result = malloc(sizeof(IWORD) * 52);
	KEY_PTR keyCopy;
	int i, j, max = 8;
	for (i = 0; i < IDEA_KEY_SIZE; i++)
		keyCopy[i] = key[i];
	
	for (i = 0; i < 7; i++)
	{
		if (i == 6)
			max = 4;
		for (j = 0; j < max; j++)
		{
			byte b1 = keyCopy[2 * j], b2 = keyCopy[2 * j + 1];
			IWORD word = b1;
			word <<= 8;
			word |= b2;
			result[i * 8 + j] = word;
		}
		if (i == 6)
			break;
		byte b1 = keyCopy[0], b2 = keyCopy[1], b3 = keyCopy[2];
		for (j = 3; j < 16; j++)
			keyCopy[j - 3] = keyCopy[j];
		keyCopy[13] = b1;
		keyCopy[14] = b2;
		keyCopy[15] = b3;
		
		b1 = keyCopy[0] >> 7;
		keyCopy[0] <<= 1;
		for (j = 0; j < 15; j++)
		{
			b2 = keyCopy[j + 1] >> 7;
			keyCopy[j + 1] <<= 1;
			keyCopy[j] |= b2;
		}
		keyCopy[15] |= b1;
	}

	if (type == CODecrypt)
	{
		IWORD *buffer = malloc(sizeof(IWORD) * 52);
		for (i = 0; i < 52; i++)
			buffer[i] = result[i];
		
		byte indexes[2] = {0, 3};
		byte index, start;
		
		// block 'multiplicative'
		for (i = 0; i < 2; i++)
		{
			index = indexes[i];
			start = index;
			for (j = 0; j < 9; j++)
			{
				result[index] = evclid_ext(buffer[(8 - j) * 6 + start], 65537);
				index += 6;
			}
		}
		// end block
		
		// block 'additive'
		result[1] = 65536 - buffer[49];
		index = 7;
		for (i = 0; i < 8; i++)
		{
			result[index] = 65536 - buffer[(7 - i) * 6 + 2];
			index += 6;
		}
		
		result[2] = 65536 - buffer[50];
		index = 8;
		for (i = 0; i < 8; i++)
		{
			result[index] = 65536 - buffer[(7 - i) * 6 + 1];
			index += 6;
		}

		IWORD tmp = result[49];
		result[49] = result[50];
		result[50] = tmp;
		// end block
		
		indexes[0] = 4;
		indexes[1] = 5;
		for (i = 0; i < 2; i++)
		{
			index = indexes[i];
			start = index;
			for (j = 0; j < 8; j++)
			{
				result[index] = buffer[(7 - j) * 6 + start];
				index += 6;
			}
		}
		free(buffer);
	}
	return result;
}

BUFF_INT idea_get_ctext_size(BUFF_INT size)
{
	BUFF_INT result = size;
	short modulo = size % IDEA_BLOCK_SIZE;
	if (modulo)
		result += IDEA_BLOCK_SIZE - modulo;
	result += IDEA_BLOCK_SIZE * 2;
	return result;
}

BUFF_INT idea_normalize_data(byte *data, BUFF_INT realSize)
{
	BUFF_INT newSize = realSize;
	short modulo = realSize % IDEA_BLOCK_SIZE;
	if (modulo)
	{
		// расширяем data до размера, кратного размеру блока
		short diff = IDEA_BLOCK_SIZE - modulo;
		for (short i = 0; i < diff; i++)
			data[realSize + i] = 0;
		newSize += diff;
	}
	
	/*
		добавляем realSize к data (записываем в конец)
		стоит заметить, что записываются десятичные цифры справа налево, т.к.
		на различных архитектурах процессоров числа в памяти хранятся по-разному
	*/
	BUFF_INT tmp = realSize, fgCounter = 0;
	while (tmp && fgCounter < IDEA_BLOCK_SIZE * 2)
	{
		byte figure = tmp % 10;
		data[newSize + fgCounter] = figure;
		fgCounter++;
		tmp /= 10;
	}
	data[newSize + fgCounter] = 0x63;
	
	return idea_get_ctext_size(realSize) / IDEA_BLOCK_SIZE;
}

BUFF_INT pow10(unsigned int n)
{
	BUFF_INT result = 1;
	if (n)
	{
		while (n)
		{
			result *= 10;
			n--;
		}
	}
	return result;
}
