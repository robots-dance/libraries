#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "diff.h"
#include "idea.h"
#include "iutils.h"

/*
	IDEA Encryptor v0.1
*/

typedef enum {
	OpTypeOption,
	KeyOption,
	InputFileOption,
	OutputFileOption
} AppOption;

typedef struct {
	char *name;
	char *value;
} Option;

typedef enum {
	NoErrors = 0,
	NoOptions, // опций запуска нет
	IncorrectOrder, // несколько значений опций подряд
	RequiredOptionNotFinded, // обязательная опция не найдена
	UnknownOption, // неизвестная опция
	BadOptionValue
} ParseError;

typedef struct {
	CryptOperationType type;
	KEY_PTR key;
	FILE *inpf;
	FILE *outf;
	int iterations;
} opts_st;

bool arg_is_bsd_option(char *arg)
{
	bool result = false;
	if (arg && strlen(arg) > 2)
		result = arg[0] == '-' && arg[1] == '-' && arg[2] != '-';
	return result;
}

bool arg_is_gnu_option(char *arg)
{
	bool result = false;
	if (arg && strlen(arg) > 1)
		result = arg[0] =='-' && arg[1] != '-';
	return result;
}

bool arg_is_option(char *arg)
{
	return arg_is_bsd_option(arg) || arg_is_gnu_option(arg);
}

opts_st *parse_cmd_args(int argc, char **argv, int *errcode, char **errinfo)
{
	opts_st *result = NULL;
	const char *allowedOptions[5] = {"-t", "-key", "-if", "-of", "-itr"};
	const int allowedAmount = sizeof(allowedOptions) / sizeof(char*);
	const int optionalIndex = 4;
	/*
		Предполагается, что все обязательные опции должны иметь значение - иначе
		зачем они тогда обязательные?
	*/
	int error = 0, state = -1;
	char *_errInfo = NULL, *localErrInfo = NULL;
	int matrix[2][2] =
	{
		/*
			всего два состояния - опция (O) или не опция (NO)
				(значение опции)
			Строки: O NO
			Столбцы: O NO
			
			666 - ошибка
			256 - finish
		*/
		{0, 1},
		{0, 666} // подряд два NO - непорядок!
	};
	Option *options = malloc(sizeof(Option) * argc);

	int i = 1, optCntr = 0;
	byte colNumber;
	while (state != 666 && i < argc)
	{
		char *arg = argv[i];
		if (arg_is_option(arg))
			colNumber = 0;
		else
			colNumber = 1;
		
		if (state < 0)
			state = !colNumber ? 0 : 666;
		else
			state = matrix[state][colNumber];

		if (!state)
		{
			options[optCntr].name = arg;
			options[optCntr].value = NULL;
			optCntr++;
		}
		else if (state == 1 && optCntr > 0)
			options[optCntr - 1].value = arg;
		i++;
	}
	if (state == 666)
		error = IncorrectOrder;
	else if (!optCntr)
		error = NoOptions;
	else
	{
		bool finded = true;
		i = 0;
		while (finded && i < optCntr)
		{
			char *optName = options[i].name;
			finded = false;
			int j = 0;
			while (!finded && j < allowedAmount)
			{
				finded = !strcmp(optName, allowedOptions[j]);
				j++;
			}
			i++;
		}
		if (!finded)
			error = UnknownOption;
		else
		{
			finded = true;
			i = 0;
			char *optName, *optValue;
			const char *allwOptName;
			while (finded && !error && i < allowedAmount)
			{
				allwOptName = allowedOptions[i];
				finded = false;
				int j = 0;
				while (!finded && !error && j < optCntr)
				{
					optName = options[j].name;
					finded = !strcmp(allwOptName, optName);
					if (finded)
					{
						optValue = options[j].value;
						if (!optValue)
							error = BadOptionValue;
						else
						{
							if (!result)
								result = malloc(sizeof(opts_st));
							switch (i) // i - счетчик в requiredOptions
							{
								case 0: // -t
									if (!strcmp(optValue, "enc"))
										result->type = COEncrypt;
									else if (!strcmp(optValue, "dec"))
										result->type= CODecrypt;
									else
										error = BadOptionValue;
								break;
								
								case 1: // -key
									if (strlen(optValue) < IDEA_KEY_SIZE)
										error = BadOptionValue;
									else
										memcpy(result->key, optValue, IDEA_KEY_SIZE);
								break;
								
								case 2: // -if
								{
									FILE *file = fopen(optValue, "r");
									if (file)
										result->inpf = file;
									else
										error = BadOptionValue;
								}
								break;
								
								case 3: // -of
								{
									FILE *file = fopen(optValue, "w");
									if (file)
										result->outf = file;
									else
										error = BadOptionValue;
								}
								break;

								case 4: // -itr
								{
									int itr = atoi(optValue);
									if (!itr)
									{
										if (optValue[0] != '0' || strlen(optValue) > 1)
											error = BadOptionValue;
									}
									if (!error)
										result->iterations = itr;
								}
								break;
							}
						}
					}
					j++;
				}
				if (i >= optionalIndex)
					finded = true;
				i++;
			}
			if (!finded || error == BadOptionValue)
			{
				localErrInfo = (char*)allwOptName;
				if (!finded)
					error = RequiredOptionNotFinded;
			}
		}
	}
	*errcode = error;
	if (localErrInfo)
	{
		int errInfoLen = strlen(localErrInfo);
		_errInfo = malloc(errInfoLen + 1);
		_errInfo[errInfoLen] = 0;
		memcpy(_errInfo, localErrInfo, errInfoLen);
	}
	*errinfo = _errInfo;
	free(options);
	return result;
}

int main(int argc, char **argv)
{
	/*
		Обязательные аргументы
			-t тип операции (CryptOperationType)
			-key ключ
			-if входной файл
			-of выходной файл
		
		Необязательные аргументы:
			-itr количество повторов (для тестирования скорости шифрования)
		
		Пример запуска программы:
			./encryptor -if /root/input.txt -t enc -of /root/out -key 0123456789abcdef -itr 2000
	*/
	int error;
	char *extErrInfo, *errmess;
	opts_st *args = parse_cmd_args(argc, argv, &error, &extErrInfo);
	if (!args || error)
	{
		switch (error)
		{
			case NoOptions:
				errmess = "**no options**";
			break;
			
			case IncorrectOrder:
				errmess = "parse error";
			break;
			
			case RequiredOptionNotFinded:
				errmess = "required option not finded";
			break;
			
			case UnknownOption:
				errmess = "unknown option";
			break;
			
			case BadOptionValue:
				errmess = "bad option value";
			break;
			
			default: errmess = "unknown error";
		}
		if (error == NoOptions || error == IncorrectOrder || error > BadOptionValue || !extErrInfo)
			printf("%s\n", errmess);
		else
		{
			printf("%s: [%s]\n", errmess, extErrInfo);
			free(extErrInfo);
		}
		return error;
	}
	BUFF_INT inpSize, outSize = 0;
	byte *data = read_file_data(args->inpf, &inpSize), *result = NULL;
	int cntr = args->iterations;
	printf("%d\n", cntr);
	if (cntr <= 0)
		cntr = 1;
	CryptOperationType type = args->type;
	IWORD *keyShedule = idea_get_keys(args->key, type);
	time_t startTime, endTime;
	startTime = time(&startTime);
	printf("input file size: %ld\n", inpSize);
	if (type == COEncrypt)
		inpSize = idea_normalize_data(data, inpSize) * IDEA_BLOCK_SIZE;
	while (cntr > 0)
	{
		if (type == COEncrypt)
		{
			result = idea_crypt_data(data, NULL, keyShedule, inpSize, false, &outSize, NULL, type);
		}
		else
		{
			if (!outSize)
				result = idea_crypt_data(data, NULL, keyShedule, inpSize, true, &outSize, NULL, type);
			else
				result = idea_crypt_data(data, NULL, keyShedule, inpSize, false, NULL, NULL, type);
		}
		if (cntr > 1)
			free(result);
		cntr--;
	}
	endTime = time(&endTime);
	printf("out file size: %ld\n", outSize);
	printf("time: %d\n", (int)(endTime - startTime));
	write_file_data(args->outf, result, outSize);
	fclose(args->inpf);
	fclose(args->outf);
	endTime = time(&endTime);
	return 0;
}
