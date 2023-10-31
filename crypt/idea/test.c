#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "diff.h"
#include "idea.h"

#define CHECK_POINT 10000
#define PORTION_SIZE (IDEA_BLOCK_SIZE * 12)

int main()
{
	KEY_PTR key = {0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8};
	
	IWORD *decKeys, *encKeys;
	encKeys = idea_get_keys(key, COEncrypt);
	//idea_dbg_print_keys(encKeys);
	decKeys = idea_get_keys(key, CODecrypt);
	//idea_dbg_print_keys(decKeys);
	byte data[PORTION_SIZE], tmp[PORTION_SIZE];
	BUFF_INT outSize;
	bool success = true;
	int i = 0;
	
	randInit();
	
	unsigned long cntr = 1;
	while (success && cntr)
	{
		if (!(cntr % CHECK_POINT))
			printf("success at %ld\n", cntr);
		
		// block 'generating material'
		for (i = 0; i < PORTION_SIZE; i++)
		{
			byte next = (byte)randEx(0, 255);
			data[i] = tmp[i] = next;
		}
		// end block
		
		// encrypt
		idea_crypt_data(data, NULL, encKeys, PORTION_SIZE, false, NULL, data, COEncrypt);
		
		// decrypt
		idea_crypt_data(data, NULL, decKeys, PORTION_SIZE, false, NULL, data, CODecrypt);
		
		// block 'checking'
		i = 0;
		while (success && i < PORTION_SIZE)
		{
			success = data[i] == tmp[i];
			i++;
		}
		// end block
		cntr++;
	}
	if (!success)
		printf("error!\n");
	return 0;
}
