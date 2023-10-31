#include <string.h>
#include "sha256.h"

#define DATA_LEN_SIZE 8
#define W_ARR_SIZE 64

#define K0  0x428a2f98
#define K1  0x71374491
#define K2  0xb5c0fbcf
#define K3  0xe9b5dba5
#define K4  0x3956c25b
#define K5  0x59f111f1
#define K6  0x923f82a4
#define K7  0xab1c5ed5
#define K8  0xd807aa98
#define K9  0x12835b01
#define K10 0x243185be
#define K11 0x550c7dc3
#define K12 0x72be5d74
#define K13 0x80deb1fe
#define K14 0x9bdc06a7
#define K15 0xc19bf174
#define K16 0xe49b69c1
#define K17 0xefbe4786
#define K18 0x0fc19dc6
#define K19 0x240ca1cc
#define K20 0x2de92c6f
#define K21 0x4a7484aa
#define K22 0x5cb0a9dc
#define K23 0x76f988da
#define K24 0x983e5152
#define K25 0xa831c66d
#define K26 0xb00327c8
#define K27 0xbf597fc7
#define K28 0xc6e00bf3
#define K29 0xd5a79147
#define K30 0x06ca6351
#define K31 0x14292967
#define K32 0x27b70a85
#define K33 0x2e1b2138
#define K34 0x4d2c6dfc
#define K35 0x53380d13
#define K36 0x650a7354
#define K37 0x766a0abb
#define K38 0x81c2c92e
#define K39 0x92722c85
#define K40 0xa2bfe8a1
#define K41 0xa81a664b
#define K42 0xc24b8b70
#define K43 0xc76c51a3
#define K44 0xd192e819
#define K45 0xd6990624
#define K46 0xf40e3585
#define K47 0x106aa070
#define K48 0x19a4c116
#define K49 0x1e376c08
#define K50 0x2748774c
#define K51 0x34b0bcb5
#define K52 0x391c0cb3
#define K53 0x4ed8aa4a
#define K54 0x5b9cca4f
#define K55 0x682e6ff3
#define K56 0x748f82ee
#define K57 0x78a5636f
#define K58 0x84c87814
#define K59 0x8cc70208
#define K60 0x90befffa
#define K61 0xa4506ceb
#define K62 0xbef9a3f7
#define K63 0xc67178f2

#define Ch( X, Y, Z ) ( ( X & Y ) ^ ( ~X & Z ) )
#define Maj( X, Y, Z ) ( ( X & Y ) ^ ( X & Z ) ^ ( Y & Z ) )

#define ROTR( x, n ) ( ( x >> n ) | ( x << ( 32 - n ) ) )

#define SIGMA0( x ) ( ROTR( x, 2 ) ^ ROTR( x, 13 ) ^ ROTR( x, 22 ) )
#define SIGMA1( x ) ( ROTR( x, 6 ) ^ ROTR( x, 11 ) ^ ROTR( x, 25 ) ) 
#define sigma0( x ) ( ROTR( x, 7 ) ^ ROTR( x, 18 ) ^ ( ( x ) >> 3 ) )
#define sigma1( x ) ( ROTR( x, 17 ) ^ ROTR( x, 19 ) ^ ( ( x ) >> 10 ) )

#define ROUND( W, K ) do { \
	UINT T1 = H + SIGMA1( E ) + Ch( E, F, G ) + K + W; \
	UINT T2 = SIGMA0( A ) + Maj( A, B, C ); \
	H = G; \
	G = F; \
	F = E; \
	E = D + T1; \
	D = C; \
	C = B; \
	B = A; \
	A = T1 + T2; \
} while( 0 );

#define GET_BYTE( x, bits ) ( ( byte_t )( ( x ) >> ( bits ) ) )

void SHA224_GetHash( SHA256_CTX *ctx, byte_t *output )
{
	UINT A = ctx->A;
	UINT B = ctx->B;
	UINT C = ctx->C;
	UINT D = ctx->D;
	UINT E = ctx->E;
	UINT F = ctx->F;
	UINT G = ctx->G;
	
	output[ 0 ] = GET_BYTE( A, 24 );
	output[ 1 ] = GET_BYTE( A, 16 );
	output[ 2 ] = GET_BYTE( A, 8 );
	output[ 3 ] = GET_BYTE( A, 0 );
	
	output[ 4 ] = GET_BYTE( B, 24 );
	output[ 5 ] = GET_BYTE( B, 16 );
	output[ 6 ] = GET_BYTE( B, 8 );
	output[ 7 ] = GET_BYTE( B, 0 );
	
	output[ 8 ] = GET_BYTE( C, 24 );
	output[ 9 ] = GET_BYTE( C, 16 );
	output[ 10 ] = GET_BYTE( C, 8 );
	output[ 11 ] = GET_BYTE( C, 0 );
	
	output[ 12 ] = GET_BYTE( D, 24 );
	output[ 13 ] = GET_BYTE( D, 16 );
	output[ 14 ] = GET_BYTE( D, 8 );
	output[ 15 ] = GET_BYTE( D, 0 );
	
	output[ 16 ] = GET_BYTE( E, 24 );
	output[ 17 ] = GET_BYTE( E, 16 );
	output[ 18 ] = GET_BYTE( E, 8 );
	output[ 19 ] = GET_BYTE( E, 0 );
	
	output[ 20 ] = GET_BYTE( F, 24 );
	output[ 21 ] = GET_BYTE( F, 16 );
	output[ 22 ] = GET_BYTE( F, 8 );
	output[ 23 ] = GET_BYTE( F, 0 );
	
	output[ 24 ] = GET_BYTE( G, 24 ); 
	output[ 25 ] = GET_BYTE( G, 16 );
	output[ 26 ] = GET_BYTE( G, 8 );
	output[ 27 ] = GET_BYTE( G, 0 );
}

void SHA256_GetHash( SHA256_CTX *ctx, byte_t *output )
{
	SHA224_GetHash( ctx, output );
	
	UINT H = ctx->H;
	
	output[ 28 ] = GET_BYTE( H, 24 );
	output[ 29 ] = GET_BYTE( H, 16 );
	output[ 30 ] = GET_BYTE( H, 8 );
	output[ 31 ] = GET_BYTE( H, 0 );
}

void SHA224_Init( SHA256_CTX *ctx )
{
	ctx->A = 0xc1059ed8;
	ctx->B = 0x367cd507;
	ctx->C = 0x3070dd17;
	ctx->D = 0xf70e5939;
	ctx->E = 0xffc00b31;
	ctx->F = 0x68581511;
	ctx->G = 0x64f98fa7;
	ctx->H = 0xbefa4fa4;
	ctx->remainSize = 0;
	ctx->overallSize = 0;
	ctx->digestSize = 224;
}

void SHA256_Init( SHA256_CTX *ctx )
{
	ctx->A = 0x6a09e667;
	ctx->B = 0xbb67ae85;
	ctx->C = 0x3c6ef372;
	ctx->D = 0xa54ff53a;
	ctx->E = 0x510e527f;
	ctx->F = 0x9b05688c;
	ctx->G = 0x1f83d9ab;
	ctx->H = 0x5be0cd19;
	ctx->remainSize = 0;
	ctx->overallSize = 0;
	ctx->digestSize = 256;
}

UpdateState SHA256_Update( SHA256_CTX *ctx, const byte_t *data,
	size_t size )
{
	if ( NULL == data || 0 == size )
	{
		return e_BadParams;
	}
	ctx->overallSize += size;
	int remainSize = ctx->remainSize;
	int freeSpaceSize = SHA256_BLOCK_SIZE - remainSize;
	byte_t bufferIsEmpty = SHA256_BLOCK_SIZE == freeSpaceSize ? 1 : 0; 
	byte_t *remainData = ctx->remainData;
	byte_t *curData = ( byte_t* )data;
	if ( size < freeSpaceSize )
	{
		memcpy( remainData + remainSize, curData, size );
		ctx->remainSize += size;
		return e_NoBufferFilled;
	}
	else if ( !bufferIsEmpty )
	{
		memcpy( remainData + remainSize, curData, freeSpaceSize );
	}
	
	size_t blocksCount = ( size - freeSpaceSize ) / SHA256_BLOCK_SIZE + 1;
	if ( !bufferIsEmpty ) {
		curData += freeSpaceSize; 
	}
	
	size_t blockIndex = 0;
	byte_t *block = !bufferIsEmpty ? remainData : curData; 
	
	UINT W[ W_ARR_SIZE ];
	
	do
	{
		UINT A = ctx->A; 
		UINT B = ctx->B;
		UINT C = ctx->C;
		UINT D = ctx->D;
		UINT E = ctx->E;
		UINT F = ctx->F;
		UINT G = ctx->G;
		UINT H = ctx->H;
		
		for ( int wordIndex = 0; wordIndex < 16; wordIndex++ )
		{
			UINT wordOffset = wordIndex * sizeof( UINT );
			W[ wordIndex ] = ( block[ wordOffset ] << 24 ) |
				( block[ wordOffset + 1 ] << 16 ) |
				( block[ wordOffset + 2 ] << 8 ) |
				block[ wordOffset + 3 ];
		}
		
		for ( int wordIndex = 16; wordIndex < W_ARR_SIZE; wordIndex++ )
		{
			UINT arg0 = W[ wordIndex - 2 ];
			UINT arg1 = W[ wordIndex - 15 ];
			W[ wordIndex ] = sigma1( arg0 ) + W[ wordIndex - 7 ] +
				sigma0( arg1 ) + W[ wordIndex - 16 ];
		}
		
		ROUND( W[ 0 ], K0 );
		ROUND( W[ 1 ], K1 );
		ROUND( W[ 2 ], K2 );
		ROUND( W[ 3 ], K3 );
		ROUND( W[ 4 ], K4 );
		ROUND( W[ 5 ], K5 );
		ROUND( W[ 6 ], K6 );
		ROUND( W[ 7 ], K7 );
		ROUND( W[ 8 ], K8 );
		ROUND( W[ 9 ], K9 );
		ROUND( W[ 10 ], K10 );
		ROUND( W[ 11 ], K11 );
		ROUND( W[ 12 ], K12 );
		ROUND( W[ 13 ], K13 );
		ROUND( W[ 14 ], K14 );
		ROUND( W[ 15 ], K15 );
		ROUND( W[ 16 ], K16 );
		ROUND( W[ 17 ], K17 );
		ROUND( W[ 18 ], K18 );
		ROUND( W[ 19 ], K19 );
		ROUND( W[ 20 ], K20 );
		ROUND( W[ 21 ], K21 );
		ROUND( W[ 22 ], K22 );
		ROUND( W[ 23 ], K23 );
		ROUND( W[ 24 ], K24 );
		ROUND( W[ 25 ], K25 );
		ROUND( W[ 26 ], K26 );
		ROUND( W[ 27 ], K27 );
		ROUND( W[ 28 ], K28 );
		ROUND( W[ 29 ], K29 );
		ROUND( W[ 30 ], K30 );
		ROUND( W[ 31 ], K31 );
		ROUND( W[ 32 ], K32 );
		ROUND( W[ 33 ], K33 );
		ROUND( W[ 34 ], K34 );
		ROUND( W[ 35 ], K35 );
		ROUND( W[ 36 ], K36 );
		ROUND( W[ 37 ], K37 );
		ROUND( W[ 38 ], K38 );
		ROUND( W[ 39 ], K39 );
		ROUND( W[ 40 ], K40 );
		ROUND( W[ 41 ], K41 );
		ROUND( W[ 42 ], K42 );
		ROUND( W[ 43 ], K43 );
		ROUND( W[ 44 ], K44 );
		ROUND( W[ 45 ], K45 );
		ROUND( W[ 46 ], K46 );
		ROUND( W[ 47 ], K47 );
		ROUND( W[ 48 ], K48 );
		ROUND( W[ 49 ], K49 );
		ROUND( W[ 50 ], K50 );
		ROUND( W[ 51 ], K51 );
		ROUND( W[ 52 ], K52 );
		ROUND( W[ 53 ], K53 );
		ROUND( W[ 54 ], K54 );
		ROUND( W[ 55 ], K55 );
		ROUND( W[ 56 ], K56 );
		ROUND( W[ 57 ], K57 );
		ROUND( W[ 58 ], K58 );
		ROUND( W[ 59 ], K59 );
		ROUND( W[ 60 ], K60 );
		ROUND( W[ 61 ], K61 );
		ROUND( W[ 62 ], K62 );
		ROUND( W[ 63 ], K63 );
		
		ctx->A += A;
		ctx->B += B;
		ctx->C += C;
		ctx->D += D;
		ctx->E += E;
		ctx->F += F;
		ctx->G += G;
		ctx->H += H;
		
		size_t blockOffset = !bufferIsEmpty ? blockIndex : blockIndex + 1;
		block = curData + blockOffset * SHA256_BLOCK_SIZE;
		blockIndex++;
	}
	while ( blockIndex < blocksCount  );
	
	curData += blocksCount * SHA256_BLOCK_SIZE; 
	if ( !bufferIsEmpty ) {
		curData -= SHA256_BLOCK_SIZE; 
	}
	int newRemainSize;
	if ( !bufferIsEmpty )
	{
		newRemainSize = ( size - freeSpaceSize ) % SHA256_BLOCK_SIZE;  
	}
	else {
		newRemainSize = size % SHA256_BLOCK_SIZE; 
	}
	if ( newRemainSize > 0 ) {
		memcpy( remainData, curData, newRemainSize );
	}
	ctx->remainSize = newRemainSize;
	
	return e_UpdateSuccess;
}

void SHA256_Final( byte_t *outputHash, SHA256_CTX *ctx )
{
	byte_t finitData[ SHA256_BLOCK_SIZE * 2 ];
	byte_t zeroData[ SHA256_BLOCK_SIZE ] = { 0 };
	
	int finitDataSize;
	ctx->remainData[ ctx->remainSize++ ] = 0x80;
	int remainSize = ctx->remainSize;
	if ( SHA256_BLOCK_SIZE - remainSize >= DATA_LEN_SIZE )
	{
		finitDataSize = SHA256_BLOCK_SIZE;
	}
	else {
		finitDataSize = sizeof( finitData );
	}
	
	int zeroesSize = finitDataSize - remainSize - DATA_LEN_SIZE;
	memcpy( finitData, ctx->remainData, remainSize );
	if ( zeroesSize > 0 ) {
		memcpy( finitData + remainSize, zeroData, zeroesSize );
	}
	
	byte_t *dataLenData = finitData + remainSize + zeroesSize;
	INT64 overallSize = ctx->overallSize * 8;
	dataLenData[ 0 ] = GET_BYTE( overallSize, 56 );
	dataLenData[ 1 ] = GET_BYTE( overallSize, 48 );
	dataLenData[ 2 ] = GET_BYTE( overallSize, 40 );
	dataLenData[ 3 ] = GET_BYTE( overallSize, 32 );
	dataLenData[ 4 ] = GET_BYTE( overallSize, 24 );
	dataLenData[ 5 ] = GET_BYTE( overallSize, 16 );
	dataLenData[ 6 ] = GET_BYTE( overallSize, 8 );
	dataLenData[ 7 ] = GET_BYTE( overallSize, 0 );
	ctx->remainSize = 0;
	
	SHA256_Update( ctx, finitData, finitDataSize );
	if ( 224 == ctx->digestSize )
	{
		SHA224_GetHash( ctx, outputHash );
	}
	else
	{
		SHA256_GetHash( ctx, outputHash );
	}
}
