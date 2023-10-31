#ifndef _SHA1_H_
#define _SHA1_H_

#define DIGEST_SIZE 20 // in bytes
#define SHA1_BLOCK_SIZE 64 // in bytes

#ifdef _MSC_VER
typedef __int64 INT64;
#else
#include <inttypes.h>
typedef int64_t INT64;
#endif

typedef unsigned char byte_t;

typedef unsigned int UINT;

typedef struct _SHA1_CTX {
	UINT A;
	UINT B;
	UINT C;
	UINT D;
	UINT E;
	byte_t remainData[ SHA1_BLOCK_SIZE ];
	int remainSize;
	INT64 overallSize;
} SHA1_CTX;

typedef enum _UpdateState {
	e_BadParams,
	e_NoBufferFilled,
	e_UpdateSuccess
} UpdateState;

void SHA1_Init( SHA1_CTX *ctx );
UpdateState SHA1_Update( SHA1_CTX *ctx, const byte_t *data, size_t size );
void SHA1_Final( byte_t *outHash, SHA1_CTX *ctx );

#endif // _SHA1_H_

