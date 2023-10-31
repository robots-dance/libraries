#ifndef __IDEA_CRYPT_H__

#define __IDEA_CRYPT_H__

#define IDEA_BLOCK_SIZE 8
#define IDEA_KEY_SIZE 16

typedef enum CryptOperationType {
	COEncrypt = 0, // шифруем
	CODecrypt // расшифровываем
} CryptOperationType;

typedef long BUFF_INT;
typedef unsigned short IWORD;

#ifndef __cplusplus
	typedef enum {
		false = 0,
		true
	} bool;
#endif

#ifndef __BYTE__
	typedef unsigned char byte;
	#define __BYTE__
#endif

typedef byte KEY_PTR[IDEA_KEY_SIZE];

byte *idea_crypt_data(byte *data, byte key[IDEA_KEY_SIZE], IWORD *keysShedule, BUFF_INT inpSize, bool normalizedMode, BUFF_INT *outSize, byte *outBuff, CryptOperationType type);
/*
	@Parameters
		data - входные данные. Если флаг normalizedMode установлен, то в случае шифрования их
		размер   должен   превышать   фактический  на  3 * IDEA_BLOCK_SIZE,  т.к.  необходимо
		выровнить   данные  до  размера,  кратного размеру блока шифрования, а также добавить
		истинную длину (inpSize)

		key - ключ. Не используется, если keysShedule != NULL

		keysShedule - расписание ключей. Если NULL, то генерится внутри ф-ии из key

		inpSize - реальный размер входных данных

		normalizedMode  -  флаг режима нормализации данных. Если он активен, то при шифровании
		входные   данные  выравниваются  до  размера,  кратного  IDEA_BLOCK_SIZE,  и  в  конец
		добавляется inpSize. В противном случае предполагается, что inpSize уже кратна размеру
		блока.  При  операции  дешифрирования активность флага действует на значение outSize и
		размер возвращаемого массива данных, в противном случае outSize будет равен inpSize

		outSize - размер данных на выходе. В случае type == COEncrypt и normalizedMode == true
		можно  получить  до  вызова функцией idea_get_crypt_text_size. Если type == CODecrypt,
		то  при  неактивности  флага  normalizedMode outSize равен inpSize, в противном случае
		длина извлекается из расшифрованного сообщения

		outBuff - если не равен NULL, то все выходные данные пишутся сюда. Предполагается, что
		размер буфера равен outSize. При операции дешифрирования стоит использовать только если
		normalizedMode == false

		type - тип операции шифрования
*/

void idea_dbg_print_keys(IWORD *keys);
/*
	@Parameters
		keys - сгенерированные ключи
*/

BUFF_INT idea_get_ctext_size(BUFF_INT size);
/*
	size - реальный размер открытого сообщения
	на выходе - фактический размер зашифрованного сообщения
*/

IWORD *idea_get_keys(KEY_PTR key, CryptOperationType type);
/*
	@Parameters
		key - материал для расписания ключей

		type - тип операции шифрования
*/

BUFF_INT idea_normalize_data(byte *data, BUFF_INT realSize);
/*
	data - открытое сообщение
	realSize - размер data
	на выходе - количество блоков размера IDEA_BLOCK_SIZE из получившихся нормализованных данных
*/

#endif
