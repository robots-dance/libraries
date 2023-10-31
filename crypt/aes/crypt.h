#ifndef __CRYPT_H__

#define __CRYPT_H__

#define AES_BLOCK_SIZE 16 // в байтах

#define PRINT_BLOCK(state) do { \
	for (int i = 0; i < AES_BLOCK_SIZE; i++) \
	{ \
		if (!i || (i + 1) % 4 != 0) \
			printf("%02x ", state[i]); \
		else \
			printf("%02x\n", state[i]); \
	} \
} while(0);

#define PRINT_DATA(data, len) do { \
	for (int i = 0; i < len; i++) \
		printf("%02x ", data[i]); \
	printf("\n"); \
} while(0);

typedef enum CryptDirection {
	EncryptDirection,
	DecryptDirection
} CryptDirection;

typedef enum CryptAlgorithm {
	CRAL_AES
} CryptAlgorithm;

#ifndef BYTE_DEFINED
	typedef unsigned char byte;
	#define BYTE_DEFINED
#endif

// section 'public api'
byte *aes_crypt_data(byte *data, int blockAmount, byte *key, CryptDirection direction, int bitcount);

void aes_crypt_init();

int aes_get_cdata_size(int inpSize);

byte *tcrypt_data(byte *data, byte *key, int dataSize, int *outSize, CryptAlgorithm alg, CryptDirection direction, int bitcount);
/*
	@Parameters
		data - входные бинарные данные. Размер буфера должен превышать размер действительных данных на
			2 * AES_BLOCK_SIZE - это необходимо для сохранения настоящей длины данных + оптимизировать
			работу с памятью (не надо выделять временный буфер для расширения data)

		key - ключ для шифрования данных data. Его размер в битах должен быть равен параметру bitcount

		dataSize - подлинный размер данных

		outSize - длина данных на выходе. Действительно полезен только в случае дешифрирования, т.к.
			при шифровании размер выходных данных можно получить с помощью aes_get_cdata_size

		alg - алгоритм шифрования

		direction - направление шифрования. Существует два направления: EncryptDirection (шифрование) и
			DecryptDirection (дешифрование)

		bitcount - битность шифрования или размер ключа. Каждый алгоритм поддерживает определенный набор
			допустимых значений этого параметра
*/

// end section

#endif
