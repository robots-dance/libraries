#include <string.h>
#include "sha1.h"

#define DATA_LEN_SIZE 8
#define W_ARR_SIZE 80

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

#define FUN1( X, Y, Z ) ( ( ( X ) & ( Y ) ) | ( ( ~( X ) ) & ( Z ) ) )
#define FUN2( X, Y, Z ) ( ( X ) ^ ( Y ) ^ ( Z ) )
#define FUN3( X, Y, Z ) ( ( ( X ) & ( Y ) ) | ( ( X ) & ( Z ) ) | \
	( ( Y ) & ( Z ) ) )
#define FUN4( X, Y, Z ) FUN2( X, Y, Z )

#define ROTL( x, n ) ( ( x << ( n ) ) | ( x >> ( 32 - n ) ) )

#define ROUND( w, f, k ) do { \
	temp = ROTL( AA, 5 ) + f( BB, CC, DD ) + EE + w + k; \
	EE = DD; \
	DD = CC; \
	CC = ROTL( BB, 30 ); \
	BB = AA; \
	AA = temp; \
} while ( 0 );

#define GET_BYTE( x, bits ) ( ( byte_t )( ( x ) >> ( bits ) ) )

void SHA1_GetHash( SHA1_CTX *ctx, byte_t *output )
{
	UINT A = ctx->A;
	UINT B = ctx->B;
	UINT C = ctx->C;
	UINT D = ctx->D;
	UINT E = ctx->E;
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
}

void SHA1_Init( SHA1_CTX *ctx )
{
	ctx->A = 0x67452301;
	ctx->B = 0xEFCDAB89;
	ctx->C = 0x98BADCFE;
	ctx->D = 0x10325476;
	ctx->E = 0xC3D2E1F0;
	ctx->remainSize = 0;
	ctx->overallSize = 0;
}

UpdateState SHA1_Update( SHA1_CTX *ctx, const byte_t *data, size_t size )
{
	if ( NULL == data || size <= 0 )
	{
		return e_BadParams;
	}
	ctx->overallSize += size;
	int remainSize = ctx->remainSize;
	int freeSpaceSize = SHA1_BLOCK_SIZE - remainSize;
	byte_t bufferIsEmpty = SHA1_BLOCK_SIZE == freeSpaceSize ? 1 : 0;
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
	
	size_t blocksCount = ( size - freeSpaceSize ) / SHA1_BLOCK_SIZE + 1;
	if ( !bufferIsEmpty ) {
		curData += freeSpaceSize;
	}
	
	size_t blockIndex = 0;
	byte_t *block = !bufferIsEmpty ? remainData : curData;
	
	UINT W[ W_ARR_SIZE ];
	
	do
	{
		UINT AA = ctx->A;
		UINT BB = ctx->B;
		UINT CC = ctx->C;
		UINT DD = ctx->D;
		UINT EE = ctx->E;
		
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
			UINT word = W[ wordIndex - 3 ] ^ W[ wordIndex - 8 ] ^
				W[ wordIndex - 14 ] ^ W[ wordIndex - 16 ];
			W[ wordIndex ] = ROTL( word, 1 );
		}
		
		UINT temp;
		
		// round 1
		{
			ROUND( W[  0 ], FUN1, K1 );
			ROUND( W[  1 ], FUN1, K1 );
			ROUND( W[  2 ], FUN1, K1 );
			ROUND( W[  3 ], FUN1, K1 );
			ROUND( W[  4 ], FUN1, K1 );
			ROUND( W[  5 ], FUN1, K1 );
			ROUND( W[  6 ], FUN1, K1 );
			ROUND( W[  7 ], FUN1, K1 );
			ROUND( W[  8 ], FUN1, K1 );
			ROUND( W[  9 ], FUN1, K1 );
			ROUND( W[ 10 ], FUN1, K1 );
			ROUND( W[ 11 ], FUN1, K1 );
			ROUND( W[ 12 ], FUN1, K1 );
			ROUND( W[ 13 ], FUN1, K1 );
			ROUND( W[ 14 ], FUN1, K1 );
			ROUND( W[ 15 ], FUN1, K1 );
			ROUND( W[ 16 ], FUN1, K1 );
			ROUND( W[ 17 ], FUN1, K1 );
			ROUND( W[ 18 ], FUN1, K1 );
			ROUND( W[ 19 ], FUN1, K1 );
		}
		
		// round 2
		{
			ROUND( W[ 20 ], FUN2, K2 );
			ROUND( W[ 21 ], FUN2, K2 );
			ROUND( W[ 22 ], FUN2, K2 );
			ROUND( W[ 23 ], FUN2, K2 );
			ROUND( W[ 24 ], FUN2, K2 );
			ROUND( W[ 25 ], FUN2, K2 );
			ROUND( W[ 26 ], FUN2, K2 );
			ROUND( W[ 27 ], FUN2, K2 );
			ROUND( W[ 28 ], FUN2, K2 );
			ROUND( W[ 29 ], FUN2, K2 );
			ROUND( W[ 30 ], FUN2, K2 );
			ROUND( W[ 31 ], FUN2, K2 );
			ROUND( W[ 32 ], FUN2, K2 );
			ROUND( W[ 33 ], FUN2, K2 );
			ROUND( W[ 34 ], FUN2, K2 );
			ROUND( W[ 35 ], FUN2, K2 );
			ROUND( W[ 36 ], FUN2, K2 );
			ROUND( W[ 37 ], FUN2, K2 );
			ROUND( W[ 38 ], FUN2, K2 );
			ROUND( W[ 39 ], FUN2, K2 );
		}
		
		// round 3
		{
			ROUND( W[ 40 ], FUN3, K3 );
			ROUND( W[ 41 ], FUN3, K3 );
			ROUND( W[ 42 ], FUN3, K3 );
			ROUND( W[ 43 ], FUN3, K3 );
			ROUND( W[ 44 ], FUN3, K3 );
			ROUND( W[ 45 ], FUN3, K3 );
			ROUND( W[ 46 ], FUN3, K3 );
			ROUND( W[ 47 ], FUN3, K3 );
			ROUND( W[ 48 ], FUN3, K3 );
			ROUND( W[ 49 ], FUN3, K3 );
			ROUND( W[ 50 ], FUN3, K3 );
			ROUND( W[ 51 ], FUN3, K3 );
			ROUND( W[ 52 ], FUN3, K3 );
			ROUND( W[ 53 ], FUN3, K3 );
			ROUND( W[ 54 ], FUN3, K3 );
			ROUND( W[ 55 ], FUN3, K3 );
			ROUND( W[ 56 ], FUN3, K3 );
			ROUND( W[ 57 ], FUN3, K3 );
			ROUND( W[ 58 ], FUN3, K3 );
			ROUND( W[ 59 ], FUN3, K3 );
		}
		
		// round 4
		{
			ROUND( W[ 60 ], FUN4, K4 );
			ROUND( W[ 61 ], FUN4, K4 );
			ROUND( W[ 62 ], FUN4, K4 );
			ROUND( W[ 63 ], FUN4, K4 );
			ROUND( W[ 64 ], FUN4, K4 );
			ROUND( W[ 65 ], FUN4, K4 );
			ROUND( W[ 66 ], FUN4, K4 );
			ROUND( W[ 67 ], FUN4, K4 );
			ROUND( W[ 68 ], FUN4, K4 );
			ROUND( W[ 69 ], FUN4, K4 );
			ROUND( W[ 70 ], FUN4, K4 );
			ROUND( W[ 71 ], FUN4, K4 );
			ROUND( W[ 72 ], FUN4, K4 );
			ROUND( W[ 73 ], FUN4, K4 );
			ROUND( W[ 74 ], FUN4, K4 );
			ROUND( W[ 75 ], FUN4, K4 );
			ROUND( W[ 76 ], FUN4, K4 );
			ROUND( W[ 77 ], FUN4, K4 );
			ROUND( W[ 78 ], FUN4, K4 );
			ROUND( W[ 79 ], FUN4, K4 );
		}
		
		ctx->A += AA;
		ctx->B += BB;
		ctx->C += CC;
		ctx->D += DD;
		ctx->E += EE;
		
		size_t blockOffset = !bufferIsEmpty ? blockIndex : blockIndex + 1;
		block = curData + blockOffset * SHA1_BLOCK_SIZE;
		blockIndex++;
	}
	while ( blockIndex < blocksCount );
	
	curData += blocksCount * SHA1_BLOCK_SIZE;
	if ( !bufferIsEmpty ) {
		curData -= SHA1_BLOCK_SIZE;
	}
	int newRemainSize; 
	if ( !bufferIsEmpty ) {
		newRemainSize = ( size - freeSpaceSize ) % SHA1_BLOCK_SIZE; 
	}
	else {
		newRemainSize = size % SHA1_BLOCK_SIZE;
	}
	if ( newRemainSize > 0 ) {
		memcpy( remainData, curData, newRemainSize );
	}
	ctx->remainSize = newRemainSize;
	
	return e_UpdateSuccess;
}

void SHA1_Final( byte_t *outputHash, SHA1_CTX *ctx )
{
	byte_t finitData[ SHA1_BLOCK_SIZE * 2 ];
	byte_t zeroData[ SHA1_BLOCK_SIZE ] = { 0 };
	int finitDataSize;
	ctx->remainData[ ctx->remainSize++ ] = 0x80;
	int remainSize = ctx->remainSize;
	if ( SHA1_BLOCK_SIZE - remainSize >= DATA_LEN_SIZE )
	{
		finitDataSize = SHA1_BLOCK_SIZE;
	}
	else
	{
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
	SHA1_Update( ctx, finitData, finitDataSize );
	SHA1_GetHash( ctx, outputHash );
}

