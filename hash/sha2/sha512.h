#ifndef _SHA512_H_
#define _SHA512_H_

#include <stdbool.h>

#define BYTE_BITS 8

// all sizes in bytes
#define DIGEST384_SIZE 48
#define DIGEST512_SIZE 64
#define SHA512_BLOCK_SIZE 128

#ifdef _MSC_VER
typedef __int64 INT64;
typedef unsigned __int64 UINT64;
#else
#include <inttypes.h>
typedef int64_t INT64;
typedef uint64_t UINT64;
#endif

typedef unsigned char byte_t;

typedef unsigned int UINT;

typedef struct {
	INT64 high;
	UINT64 low;
} INT128;

typedef struct _SHA512_CTX {
	UINT64 A;
	UINT64 B;
	UINT64 C;
	UINT64 D;
	UINT64 E;
	UINT64 F;
	UINT64 G;
	UINT64 H;
	byte_t remainData[ SHA512_BLOCK_SIZE ];
	int remainSize;
	INT128 overallSize; 
	int digestSize;
} SHA512_CTX;

typedef enum _UpdateState {
	e_BadParams,
	e_NoBufferFilled,
	e_UpdateSuccess
} UpdateState;

void SHA384_Init( SHA512_CTX *ctx );
void SHA512_Init( SHA512_CTX *ctx );
bool SHA512t_Init( SHA512_CTX *ctx, int digestSize  );
UpdateState SHA512_Update( SHA512_CTX *ctx, const byte_t *data,
	size_t size );
void SHA512_Final( byte_t *outputHash, SHA512_CTX *ctx );

#endif // _SHA512_H_ 
