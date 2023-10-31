#ifndef _MD5_H_
#define _MD5_H_

#define DIGEST_SIZE 16 // in bytes
#define MD5_BLOCK_SIZE 64 // in bytes 

#ifdef _MSC_VER
typedef __int64 INT64;
#else
#include <inttypes.h>
typedef int64_t INT64;
#endif

typedef unsigned char byte_t;

typedef unsigned int UINT;

typedef struct _MD5_CTX {
	UINT A;
	UINT B;
	UINT C;
	UINT D;
	byte_t remainData[ MD5_BLOCK_SIZE ];
	int remainSize;
	INT64 overallSize;
} MD5_CTX;

typedef enum _UpdateState {
	e_BadParams,
	e_NoBufferFilled,
	e_UpdateSuccess
} UpdateState;

void MD5_Init( MD5_CTX *ctx );
UpdateState MD5_Update( MD5_CTX *ctx, const byte_t *data, int size );
void MD5_Final( byte_t *outputHash, MD5_CTX *ctx );
void MD5_GetRepr( char *hashRepr, const byte_t *hash );

#endif // _MD5_H_

