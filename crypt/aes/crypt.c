#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"

#define PRINT_WORD(word) do {\
	for (int i = 0; i < 4; i++) \
		if (i != 3) \
			printf("%02x", word[i]); \
		else \
			printf("%02x\n", word[i]); \
} while (0);

#define ROTL(x) (((x) >> 7) | ((x) << 1))

#define true 1
#define false 0

typedef enum ShiftDirection {
	ShiftLeft,
	ShiftRight
} ShiftDirection;

typedef byte bool;


// section AES

// section 'alg steps'
void aes_add_round_key(byte *state, byte *roundKey);
byte **aes_key_expansion(byte *key, int Nk, int Nr);
void aes_mix_columns(byte *state, CryptDirection direction); // size-dependent
void aes_shift_row(byte *first, int len, int count, ShiftDirection direction);
void aes_shift_rows(byte *state, CryptDirection direction); // size-dependent
void aes_sub_bytes(byte *state, int stateSize, CryptDirection direction);

// section 'blocks'
byte *aes_get_block(byte *data, int blockIndex);
byte *aes_join_blocks(byte **blocks, int blockAmount);

// section 'gf256 operations'
byte aes_gf_inv(byte value);
byte aes_gf_mul(byte arg1, byte arg2, byte ***cache);
byte aes_gf_mul_x(byte arg, int degree);

// section 'word operations'
void aes_mov_word(byte *word, byte *result);
void aes_sub_word(byte *word);
void aes_rot_word(byte *word, byte *result);
void aes_xor_word(byte *word1, byte *word2, byte *result);


void aes_set_matrix(byte *matrix, int size, ...)
{
	va_list factor;
	va_start(factor, size);
	for (int i = 0; i < size; i++)
	{
		char value = va_arg(factor, int);
		matrix[i] = value;
	}
	va_end(factor);
}

long pow10(int n)
{
	long result = 1;
	for (int i = 0; i < n; i++)
		result *= 10;
	return result;
}

// section 'alg steps'
void aes_add_round_key(byte *state, byte *roundKey)
{
	for (int i = 0; i < AES_BLOCK_SIZE; i++)
		state[i] ^= roundKey[i];
}

byte **aes_key_expansion(byte *key, int Nk, int Nr)
{
	int keyAmount = Nr + 1;
	byte **rkeys = (byte**)malloc(sizeof(byte*) * keyAmount);
	int outSize = AES_BLOCK_SIZE * keyAmount;
	byte *out = (byte*)malloc(outSize);
	memcpy(out, key, Nk * 4);
	int i = Nk;
	int high = outSize / 4;
	byte buffer[4] = {0, 0, 0, 0}, rcon[4] = {0, 0, 0, 0};
	while (i < high)
	{
		aes_mov_word(&out[4 * (i - 1)], buffer);
		if (i % Nk == 0)
		{
			aes_rot_word(buffer, buffer);
			aes_sub_word(buffer);
			int index = i / Nk;
			if (index == 1)
				rcon[0] = 1;
			else
				rcon[0] = aes_gf_mul_x(0x1, index - 1);
			aes_xor_word(buffer, rcon, buffer);
		}
		else if (Nk > 6 && i % Nk == 4)
			aes_sub_word(buffer);
		byte *prev = &out[4 * (i - Nk)];
		aes_xor_word(buffer, prev, buffer);
		aes_mov_word(buffer, &out[4 * i]);
		i++;
	}

	byte *tmp = out;
	for (int i = 0; i < keyAmount; i++)
	{
		rkeys[i] = aes_get_block(out, i);
	}
	out = tmp;
	free(out);
	return rkeys;
}

void aes_mix_columns(byte *state, CryptDirection direction) // size-dependent
{
	static byte **GF_State = NULL;
	if (!GF_State)
		aes_gf_mul(0, 0, &GF_State);
	static byte en_matr[4][4] = {{0x02, 0x03, 0x01, 0x01}, {0x01, 0x02, 0x03, 0x01}, {0x01, 0x01, 0x02, 0x03}, {0x03, 0x01, 0x01, 0x02}};
	static byte de_matr[4][4] = {{0x0e, 0x0b, 0x0d, 0x09}, {0x09, 0x0e, 0x0b, 0x0d}, {0x0d, 0x09, 0x0e, 0x0b}, {0x0b, 0x0d, 0x09, 0x0e}};
	byte *matrix = direction == EncryptDirection ? (byte*)en_matr : (byte*)de_matr;
	byte newState[16];
	byte offsets[4] = {0, 4, 8, 12};
	for (int i = 0; i < 4; i++)
	{
		byte *start1 = &state[i];
		for (int j = 0; j < 4; j++)
		{
			byte curoffset = offsets[j];
			byte *start2 = &matrix[curoffset];
			byte part1 = GF_State[start2[0]][start1[0]]; 
			byte part2 = GF_State[start2[1]][start1[4]];
			byte part3 = GF_State[start2[2]][start1[8]];
			byte part4 = GF_State[start2[3]][start1[12]];
			newState[i + curoffset] = part1 ^ part2 ^ part3 ^ part4;
		}
	}
	memcpy(state, newState, AES_BLOCK_SIZE);
}

void aes_shift_row(byte *first, int len, int count, ShiftDirection direction)
{
	for (int i = 0; i < count; i++)
	{
		if (direction == ShiftLeft)
		{
			byte c_first = first[0];
			for (int j = 0; j < len - 1; j++)
				first[j] = first[j + 1];
			first[len - 1] = c_first;
		}
		else
		{
			byte c_last = first[len - 1];
			for (int j = len - 1; j > 0; j--)
				first[j] = first[j - 1];
			first[0] = c_last;
		}
	}
}

void aes_shift_rows(byte *state, CryptDirection direction) // size-dependent
{
	ShiftDirection shiftto;
	if (direction == EncryptDirection)
		shiftto = ShiftLeft;
	else
		shiftto = ShiftRight;
	aes_shift_row(&state[4], 4, 1, shiftto);
	aes_shift_row(&state[8], 4, 2, shiftto);
	aes_shift_row(&state[12], 4, 3, shiftto);
}

void aes_sub_bytes(byte *state, int stateSize, CryptDirection direction)
{
	static byte *sbox = NULL;
	if (!sbox)
	{
		sbox = (byte*)malloc(256);
		memset(sbox, 0, 256);
	}

	static byte *invsbox = NULL;

	if (!invsbox)
	{
		invsbox = (byte*)malloc(256);
		memset(invsbox, 0, 256);
	}

	for (int i = 0; i < stateSize; i++)
	{
		byte cur = state[i], result = 0, arg;
		arg = cur;

		if (direction == EncryptDirection)
		{
			if (cur != 0x52 && !sbox[cur])
			{
				arg = aes_gf_inv(arg);
				result = arg;
				arg = ROTL(arg); result ^= arg;
				arg = ROTL(arg); result ^= arg;
				arg = ROTL(arg); result ^= arg;
				arg = ROTL(arg); result ^= arg;
				result ^= 0x63;
				sbox[cur] = result;
			}
			else
				;//printf("1\n");
			state[i] = sbox[cur];
		}
		else
		{
			if (cur != 0x63 && !invsbox[cur])
			{
				byte bits[8] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80};
				/*
					байты с выставленными битами от 0 до 7, т.е. 0000 0001, 0000 0010, и т.д.
					Необходимы для вытаскивания битов из байтов по номеру бита - если нужен
					2-ой бит (нумерация с 1), то выражение (bits[1] & our_byte) истинно только
					тогда, когда искомый бит активен
				*/

				byte meanBits[8][3] = {{2, 5, 7}, {0, 3, 6}, {1, 4, 7}, {0, 2, 5}, {1, 3, 6}, {2, 4, 7}, {0, 3, 5}, {1, 4, 6}};
				/*
					номера значащих битов, входящих в состав выходного байта
				*/
				arg ^= 0x63;
				for (int i = 0; i < 8; i++)
				{
					byte *bitNumbers = meanBits[i]; // чтобы не прибавлялось 8 * i каждый раз
					byte unitCount = 0; 
					for (int j = 0; j < 3; j++)
					{
						if (bits[bitNumbers[j]] & arg)
						{
							unitCount++;
						}
					}
					if (unitCount % 2) // выходной i-бит активен
					result |= bits[i];
				}
				result = aes_gf_inv(result);
				invsbox[cur] = result;
			}
			else
				;//printf("1\n");
			state[i] = invsbox[cur];
		}
	}
}
// end section

// section 'blocks'
byte *aes_get_block(byte *data, int blockIndex)
{
	byte *result = (byte*)malloc(AES_BLOCK_SIZE);
	byte *first = data + blockIndex * AES_BLOCK_SIZE;
	int counter1 = 0;
	byte buffer[4];
	for (int j = 0; j < AES_BLOCK_SIZE; j += 4)
	{
		aes_mov_word(&first[j], buffer);
		for (int counter2 = 0; counter2 < 4; counter2++)
		{
			result[counter1 + counter2 * 4] = buffer[counter2];
		}
		counter1++;
	}
	return result;
}

byte *aes_join_blocks(byte **blocks, int blockAmount)
{
	byte *result = (byte*)malloc(blockAmount * AES_BLOCK_SIZE);
	int i = 0;
	int counter = 0;
	while (i < blockAmount)
	{
		byte *curBlock = blocks[i];
		for (int j = 0; j < AES_BLOCK_SIZE / 4; j++)
		{
			for (int counter1 = 0; counter1 < 4; counter1++)
			{
				result[counter] = curBlock[j + counter1 * 4];
				counter++;
			}
		}
		i++;
	}
	return result;
}
// end section

// section 'gf256 operations'
byte aes_gf_inv(byte value)
{
	if (!value)
		return 0;

	for (byte i = 0; i <= 255; i++)
		if (aes_gf_mul(value, i, NULL) == 1)
			return i;
}

byte aes_gf_mul(byte arg1, byte arg2, byte ***out)
{
	byte degreeTable[7] = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
	char real[7] = {0, 0, 0, 0, 0, 0, 0};
	byte max = arg1 >= arg2 ? arg1 : arg2;
	byte min = arg1 < arg2 ? arg1 : arg2;
	byte result = 0, degree;
	int counter = 6;

	static byte **cache = NULL;
	if (!cache)
	{
		cache = (byte**)malloc(sizeof(byte*) * 256);
		for (int i = 0; i < 256; i++)
		{
			cache[i] = (byte*)malloc(256);
			memset(cache[i], 0, 256);
		}
	}
	if (out)
		*out = cache;

	byte argIsZero = arg1 * arg2 ? 0: 1;
	if (!argIsZero && !cache[arg1][arg2])
	{
		// разбиваем многочлен на степени x
		while (counter >= 0)
		{
			degree = degreeTable[counter];
			while (min >= degree)
			{
				min -= degree;
				real[counter]++;
			}
			counter--;
		}
		for (int i = 0; i < 7; i++)
		{
			if (real[i])
			{
				byte mul = aes_gf_mul_x(max, i + 1);
				if (!result)
					result = mul;
				else
					result ^= mul;
			}
		}

		if (min)
			result = result ? result ^ max: max; 
		cache[arg1][arg2] = cache[arg2][arg1] = result;
	}
	else if (!argIsZero)
		result = cache[arg1][arg2];
	return result;
}

byte aes_gf_mul_x(byte arg, int degree)
{
	byte result = arg;
	for (int i = 0; i < degree; i++)
	{
		byte highbit = result & 0x80;
		byte shl = (result << 1) & 0xff;
		result = highbit == 0 ? shl : shl ^ 0x1b;
	}
	return result;
}
// end section

// section 'word32 operations'
void aes_mov_word(byte *word, byte *result)
{
	for (int i = 0; i < 4; i++)
		result[i] = word[i];
}

void aes_sub_word(byte *word)
{
	aes_sub_bytes(word, 4, EncryptDirection);
}

void aes_rot_word(byte *word, byte *result)
{
	byte part1 = word[0], part2 = word[1], part3 = word[2], part4 = word[3];
	result[0] = part2;
	result[1] = part3;
	result[2] = part4;
	result[3] = part1;
}

void aes_xor_word(byte *word1, byte *word2, byte *result)
{
	for (int i = 0; i < 4; i++)
	{
		result[i] = word1[i] ^ word2[i];
	}
}
// end section

// end section AES


// section 'public api'
byte *aes_crypt_data(byte *data, int blockAmount, byte *key, CryptDirection direction, int bitcount)
{
	byte *result = NULL;
	unsigned short Nk, Nr = 0;
	switch (bitcount)
	{
		case 128:
			Nr = 10;
		break;

		case 192:
			Nr = 12;
		break;

		case 256:
			Nr = 14;
		break;
	}
	if (!Nr)
		return NULL;
	Nk = bitcount / 32;
	byte **out = (byte**)malloc(sizeof(byte*) * blockAmount);
	byte **rkeys = aes_key_expansion(key, Nk, Nr);

	for (int i = 0; i < blockAmount; i++)
	{
		byte *block = aes_get_block(data, i);
		if (direction == EncryptDirection)
		{
			aes_add_round_key(block, rkeys[0]);
			for (int j = 1; j <= Nr; j++)
			{
				aes_sub_bytes(block, AES_BLOCK_SIZE, direction);
				aes_shift_rows(block, direction);
				if (j != Nr)
					aes_mix_columns(block, direction);
				aes_add_round_key(block, rkeys[j]);
			}
		}
		else
		{
			for (int j = Nr; j >= 1; j--)
			{
				aes_add_round_key(block, rkeys[j]);
				if (j != Nr)
					aes_mix_columns(block, direction);
				aes_shift_rows(block, direction);
				aes_sub_bytes(block, AES_BLOCK_SIZE, direction);
			}
			aes_add_round_key(block, rkeys[0]);
		}
		out[i] = block;
	}
	result = aes_join_blocks(out, blockAmount);
	for (int i = 0; i < blockAmount; i++)
		free(out[i]);
	free(out);
	for (int i = 0; i <= Nr; i++)
		free(rkeys[i]);
	free(rkeys);
	return result;
}

void aes_crypt_init()
{
	byte allBytes[256];
	for (int i = 0; i < 256; i++)
		allBytes[i] = i;
	aes_sub_bytes(allBytes, 256, EncryptDirection);
	aes_sub_bytes(allBytes, 256, DecryptDirection);
	for (int i = 0; i < 256; i++)
		for (int j = 0; j < 256; j++)
			aes_gf_mul(i, j, NULL);
}

int aes_get_cdata_size(int inpSize)
{
	int result = inpSize;
	int modulo = inpSize % AES_BLOCK_SIZE;
	if (modulo)
		result += abs(AES_BLOCK_SIZE - modulo);
	result += AES_BLOCK_SIZE;
	return result;
}

byte *tcrypt_data(byte *data, byte *key, int dataSize, int *outSize, CryptAlgorithm alg, CryptDirection direction, int bitcount)
{
	byte *result = NULL;
	switch (alg)
	{
		case CRAL_AES:
		{
			int realSize = dataSize;
			if (direction == EncryptDirection)
			{
				int modulo = dataSize % AES_BLOCK_SIZE;
				if (modulo != 0)
				{
					// расширяем data до размера, кратного размеру блока
					for (int i = 0; i < modulo; i++)
						data[dataSize + i] = 0;
					realSize += abs(AES_BLOCK_SIZE - modulo);
				}
				/*
					добавляем dataSize к данным, число представлено в виде последовательности
					байтов,  каждый  из  которых - это десятичная цифра числа. Получается что
					для  хранения длины необходимо больше места, но таким образом мы избегаем
					некроссплатформенного  трюка,  причина  которого  заключается  в том, что
					байты   в   процессорах  Intel  (и  intel-подобных)  хранятся  в  порядке
					little-endian, а на других платформах порядок может быть противоположным.
					Да, разряды десятичного числа хранятся от младшей к старшей
				*/
				int tmp = dataSize, figAmount = 0;
				while (tmp && figAmount < AES_BLOCK_SIZE - 1)
				{
					byte figure = tmp % 10; // гарантированно получаем младшую цифру числа
					data[realSize + figAmount] = figure;
					figAmount++;
					tmp /= 10;
				}
				data[realSize + figAmount] = 0xff; // такой десятичной цифры не существует - однозначно конец
				realSize += AES_BLOCK_SIZE;
				if (outSize)
					*outSize = realSize;
			}
			int blockAmount = realSize / AES_BLOCK_SIZE;
			result = aes_crypt_data(data, blockAmount, key, direction, bitcount);
			if (direction == DecryptDirection)
			{
				// извлекаем подлинную длину зашифрованных данных и обрезаем ненужное
				byte *lenblock = result + (blockAmount - 1) * AES_BLOCK_SIZE;
				int i = 0;
				int length = 0;
				while (i < AES_BLOCK_SIZE)
				{
					byte next = lenblock[i];
					if (next == 0xff)
						break;
					length += next * pow10(i);
					i++;
				}
				if (outSize)
					*outSize = length;
			}
		}
		break;

		default:;
	}
	return result;
}
// end section
