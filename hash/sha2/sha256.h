#ifndef _SHA256_H_
#define _SHA256_H_

// all sizes in bytes
#define DIGEST224_SIZE 28
#define DIGEST256_SIZE 32
#define SHA256_BLOCK_SIZE 64

#ifdef _MSC_VER
typedef __int64 INT64;
#else
#include <inttypes.h>
typedef int64_t INT64;
#endif

typedef unsigned char byte_t;

typedef unsigned int UINT;

typedef struct _SHA256_CTX {
	UINT A;
	UINT B;
	UINT C;
	UINT D;
	UINT E;
	UINT F;
	UINT G;
	UINT H;
	byte_t remainData[ SHA256_BLOCK_SIZE ];
	int remainSize;
	INT64 overallSize;
	int digestSize;
} SHA256_CTX;

typedef enum _UpdateState {
	e_BadParams,
	e_NoBufferFilled,
	e_UpdateSuccess
} UpdateState;

void SHA224_Init( SHA256_CTX *ctx );
void SHA256_Init( SHA256_CTX *ctx );
UpdateState SHA256_Update( SHA256_CTX *ctx, const byte_t *data,
	size_t size );
void SHA256_Final( byte_t *outputHash, SHA256_CTX *ctx );

#endif // _SHA256_H_
