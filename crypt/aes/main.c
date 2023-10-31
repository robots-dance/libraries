#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypt.h"

/*
	AES Encryptor v0.1

	Данная утилита предназначена для шифрования файлов
*/
int fileSizeModifier(int fsize)
{
	return aes_get_cdata_size(fsize);
}

byte *read_file_data(FILE *file, int *fsize, int (*sizeModifier)(int))
{
	fseek(file, 0, SEEK_END);
	int fileSize = ftell(file), byteAmount;
	fseek(file, 0, 0);
	byteAmount = fileSize;
	if (sizeModifier)
		byteAmount = sizeModifier(fileSize);
	byte *result = (byte*)malloc(byteAmount);
	int i = 0;
	while (i < fileSize)
	{
		result[i] = fgetc(file);
		i++;
	}
	*fsize = fileSize;
	return result;
}

void write_file_data(FILE *file, byte *data, int size)
{
	for (int i = 0; i < size; i++)
		fputc(data[i], file);
}

int main(int argc, char *argv[])
{
	int exitcode = 0;

	const int keySizes[3] = {128, 192, 256};

	byte *ckey;
	/*
		Обязательные аргументы:

		argv[1] - тип операции, шифрование (en) или дешифрирование (de)
		argv[2] - ключ (пароль)
		argv[3] - размер ключа (битность алгоритма)
		argv[4] - путь входного файла
		argv[5] - путь выходного файла

		Необязательные аргументы:

		argv[6] - количество циклов шифрования (тестирование производительности)
	*/

	if (argc < 6)
	{
		printf("Bad amount of arguments!\n");
		exit(1);
	}

	// определение типа операции
	char *type = argv[1];
	byte isEncryptOp = !strcmp(type, "en") ? 1 : 0;
	byte isDecryptOp = !strcmp(type, "de") ? 1 : 0;
	if (!isEncryptOp && !isDecryptOp)
	{
		printf("Incrorrect type of operation.\n");
		exit(2);
	}

	// подготовка ключа шифрования
	int ksize = atoi(argv[3]);
	byte notFinded = 0;
	int i = 0, arrsize = sizeof(keySizes);
	while (i < arrsize && notFinded)
	{
		notFinded = ksize != keySizes[i];
		i++;
	}
	if (notFinded)
	{
		printf("Incorrect key size\n");
		exit(3);
	}
	ksize /= 8;
	ckey = (byte*)malloc(ksize + 1);
	char *keyData = argv[2];
	int keyDataLen = strlen(keyData);
	if (keyDataLen < ksize)
		memcpy(ckey, keyData, keyDataLen);
	else
		memcpy(ckey, keyData, ksize);

	// подготовка входного и выходного файлов
	FILE *inpf = fopen(argv[4], "r"), *outf = fopen(argv[5], "w"); 
	if (!inpf)
	{
		printf("Can't open input file.\n");
		exit(4);
	}

	if (!outf)
	{
		printf("Can't open output file.\n");
		exit(5);
	}

	CryptDirection direction;
	int fileSize, outSize;

	if (isEncryptOp)
		direction = EncryptDirection;
	else
		direction = DecryptDirection;

	aes_crypt_init();

	if (1)
	{
		printf("reading file...\n");
		byte *fileData = read_file_data(inpf, &fileSize, fileSizeModifier), *outData;
		char *opName = direction == EncryptDirection ? "encrypt" : "decrypt";
		printf("file size: %d\n", fileSize);
		printf("doing operation %s...\n", opName);
		int cycleAm = 1;
		if (argc == 7)
			cycleAm = atoi(argv[6]);
		if (cycleAm <= 0)
			cycleAm = 1;
		time_t startTime, endTime;
		startTime = time(&startTime);
		while (cycleAm)
		{
			outData = tcrypt_data(fileData, ckey, fileSize, &outSize, CRAL_AES, direction, ksize * 8);
			if (cycleAm != 1)
				free(outData);
			cycleAm--;
		}
		endTime = time(&endTime);
		printf("time: %d\n", (int)(endTime - startTime));
		printf("writing to file..\n");
		write_file_data(outf, outData, outSize);
		printf("file size: %d\n", outSize);
		free(fileData);
		printf("done.\n");
	}
	else
		printf("init error\n");
	fclose(inpf);
	fclose(outf);
	free(ckey);
	return exitcode;
}
