#include <string.h>
#include "md5.h"

#define DATA_LEN_SIZE 8

#define FUN_F( X, Y, Z ) ( ( X & Y ) | ( ~X & Z ) )
#define FUN_G( X, Y, Z ) ( ( X & Z ) | ( ~Z & Y ) )
#define FUN_H( X, Y, Z ) ( X ^ Y ^ Z )
#define FUN_I( X, Y, Z ) ( Y ^ ( ~Z | X ) )

#define ROTL( x, n ) ( ( x << ( n ) ) | ( x >> ( 32 - n ) ) )

#define ROUND( a, b, c, d, f, x, t, s ) do { \
	a += f( b, c, d ) + x + t; \
	a = ROTL( a, s ); \
	a += b; \
} while ( 0 );

#define GET_BYTE( x, bits ) ( ( byte_t )( ( x ) >> ( bits ) ) )


void MD5_GetHash( MD5_CTX *ctx, byte_t *output )
{
	UINT A = ctx->A;
	UINT B = ctx->B;
	UINT C = ctx->C;
	UINT D = ctx->D;
	output[  0 ] = GET_BYTE( A,  0 ); 
	output[  1 ] = GET_BYTE( A,  8 ); 
	output[  2 ] = GET_BYTE( A, 16 ); 
	output[  3 ] = GET_BYTE( A, 24 ); 
	output[  4 ] = GET_BYTE( B,  0 ); 
	output[  5 ] = GET_BYTE( B,  8 );
	output[  6 ] = GET_BYTE( B, 16 );
	output[  7 ] = GET_BYTE( B, 24 );
	output[  8 ] = GET_BYTE( C,  0 );
	output[  9 ] = GET_BYTE( C,  8 );
	output[ 10 ] = GET_BYTE( C, 16 );
	output[ 11 ] = GET_BYTE( C, 24 );
	output[ 12 ] = GET_BYTE( D,  0 );
	output[ 13 ] = GET_BYTE( D,  8 );
	output[ 14 ] = GET_BYTE( D, 16 );
	output[ 15 ] = GET_BYTE( D, 24 );
}

void MD5_Init( MD5_CTX *ctx )
{
	ctx->A = 0x67452301;
	ctx->B = 0xEFCDAB89;
	ctx->C = 0x98BADCFE;
	ctx->D = 0x10325476; 
	ctx->remainSize = 0;
	ctx->overallSize = 0;
}

UpdateState MD5_Update( MD5_CTX *ctx, const byte_t *data, int size )
{
	if ( NULL == data || size <= 0 )
	{
		return e_BadParams;
	}
	ctx->overallSize += size;
	int remainSize = ctx->remainSize;
	int freeSpaceSize = MD5_BLOCK_SIZE - remainSize;
	byte_t bufferIsEmpty = MD5_BLOCK_SIZE == freeSpaceSize ? 1 : 0;
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
	
	size_t blocksCount = ( size - freeSpaceSize ) / MD5_BLOCK_SIZE + 1;
	if ( !bufferIsEmpty ) {
		curData += freeSpaceSize;
	}
	
	size_t blockIndex = 0;
	UINT X[ MD5_BLOCK_SIZE / sizeof( UINT ) ]; // 16
	byte_t *block = !bufferIsEmpty ? remainData : curData;
	do
	{
		UINT AA = ctx->A;
		UINT BB = ctx->B;
		UINT CC = ctx->C;
		UINT DD = ctx->D;
		
		int byteIndex = 0;
		for ( int wordIndex = 0;
			wordIndex < sizeof( X ) / sizeof( UINT ); // 16
			++wordIndex )
		{
			X[ wordIndex ] = block[ byteIndex ] |
				block[ byteIndex + 1 ] <<  8 |
				block[ byteIndex + 2 ] << 16 |
				block[ byteIndex + 3 ] << 24;
			byteIndex += sizeof( UINT ); 
		}
		
		// round 1
		{
			ROUND( AA, BB, CC, DD, FUN_F, X[ 0 ], 0xd76aa478, 7 );
			ROUND( DD, AA, BB, CC, FUN_F, X[ 1 ], 0xe8c7b756, 12 );
			ROUND( CC, DD, AA, BB, FUN_F, X[ 2 ], 0x242070db, 17 );
			ROUND( BB, CC, DD, AA, FUN_F, X[ 3 ], 0xc1bdceee, 22 );
			ROUND( AA, BB, CC, DD, FUN_F, X[ 4 ], 0xf57c0faf, 7 );
			ROUND( DD, AA, BB, CC, FUN_F, X[ 5 ], 0x4787c62a, 12 );
			ROUND( CC, DD, AA, BB, FUN_F, X[ 6 ], 0xa8304613, 17 );
			ROUND( BB, CC, DD, AA, FUN_F, X[ 7 ], 0xfd469501, 22 );
			ROUND( AA, BB, CC, DD, FUN_F, X[ 8 ], 0x698098d8, 7 );
			ROUND( DD, AA, BB, CC, FUN_F, X[ 9 ], 0x8b44f7af, 12 );
			ROUND( CC, DD, AA, BB, FUN_F, X[ 10 ], 0xffff5bb1, 17 );
			ROUND( BB, CC, DD, AA, FUN_F, X[ 11 ], 0x895cd7be, 22 );
			ROUND( AA, BB, CC, DD, FUN_F, X[ 12 ], 0x6b901122, 7 );
			ROUND( DD, AA, BB, CC, FUN_F, X[ 13 ], 0xfd987193, 12 );
			ROUND( CC, DD, AA, BB, FUN_F, X[ 14 ], 0xa679438e, 17 );
			ROUND( BB, CC, DD, AA, FUN_F, X[ 15 ], 0x49b40821, 22 );
		}
		
		// round 2
		{
			ROUND( AA, BB, CC, DD, FUN_G, X[ 1 ], 0xf61e2562, 5 );
			ROUND( DD, AA, BB, CC, FUN_G, X[ 6 ], 0xc040b340, 9 );
			ROUND( CC, DD, AA, BB, FUN_G, X[ 11 ], 0x265e5a51, 14 );
			ROUND( BB, CC, DD, AA, FUN_G, X[ 0 ], 0xe9b6c7aa, 20 );
			ROUND( AA, BB, CC, DD, FUN_G, X[ 5 ], 0xd62f105d, 5 );
			ROUND( DD, AA, BB, CC, FUN_G, X[ 10 ], 0x2441453, 9 );
			ROUND( CC, DD, AA, BB, FUN_G, X[ 15 ], 0xd8a1e681, 14 );
			ROUND( BB, CC, DD, AA, FUN_G, X[ 4 ], 0xe7d3fbc8, 20 );
			ROUND( AA, BB, CC, DD, FUN_G, X[ 9 ], 0x21e1cde6, 5 );
			ROUND( DD, AA, BB, CC, FUN_G, X[ 14 ], 0xc33707d6, 9 );
			ROUND( CC, DD, AA, BB, FUN_G, X[ 3 ], 0xf4d50d87, 14 );
			ROUND( BB, CC, DD, AA, FUN_G, X[ 8 ], 0x455a14ed, 20 );
			ROUND( AA, BB, CC, DD, FUN_G, X[ 13 ], 0xa9e3e905, 5 );
			ROUND( DD, AA, BB, CC, FUN_G, X[ 2 ], 0xfcefa3f8, 9 );
			ROUND( CC, DD, AA, BB, FUN_G, X[ 7 ], 0x676f02d9, 14 );
			ROUND( BB, CC, DD, AA, FUN_G, X[ 12 ], 0x8d2a4c8a, 20 );
		}
		
		// round 3
		{
			ROUND( AA, BB, CC, DD, FUN_H, X[ 5 ], 0xfffa3942, 4 );
			ROUND( DD, AA, BB, CC, FUN_H, X[ 8 ], 0x8771f681, 11 );
			ROUND( CC, DD, AA, BB, FUN_H, X[ 11 ], 0x6d9d6122, 16 );
			ROUND( BB, CC, DD, AA, FUN_H, X[ 14 ], 0xfde5380c, 23 );
			ROUND( AA, BB, CC, DD, FUN_H, X[ 1 ], 0xa4beea44, 4 );
			ROUND( DD, AA, BB, CC, FUN_H, X[ 4 ], 0x4bdecfa9, 11 );
			ROUND( CC, DD, AA, BB, FUN_H, X[ 7 ], 0xf6bb4b60, 16 );
			ROUND( BB, CC, DD, AA, FUN_H, X[ 10 ], 0xbebfbc70, 23 );
			ROUND( AA, BB, CC, DD, FUN_H, X[ 13 ], 0x289b7ec6, 4 );
			ROUND( DD, AA, BB, CC, FUN_H, X[ 0 ], 0xeaa127fa, 11 );
			ROUND( CC, DD, AA, BB, FUN_H, X[ 3 ], 0xd4ef3085, 16 );
			ROUND( BB, CC, DD, AA, FUN_H, X[ 6 ], 0x4881d05, 23 );
			ROUND( AA, BB, CC, DD, FUN_H, X[ 9 ], 0xd9d4d039, 4 );
			ROUND( DD, AA, BB, CC, FUN_H, X[ 12 ], 0xe6db99e5, 11 );
			ROUND( CC, DD, AA, BB, FUN_H, X[ 15 ], 0x1fa27cf8, 16 );
			ROUND( BB, CC, DD, AA, FUN_H, X[ 2 ], 0xc4ac5665, 23 );
		}
		
		// round 4
		{
			ROUND( AA, BB, CC, DD, FUN_I, X[ 0 ], 0xf4292244, 6 );
			ROUND( DD, AA, BB, CC, FUN_I, X[ 7 ], 0x432aff97, 10 );
			ROUND( CC, DD, AA, BB, FUN_I, X[ 14 ], 0xab9423a7, 15 );
			ROUND( BB, CC, DD, AA, FUN_I, X[ 5 ], 0xfc93a039, 21 );
			ROUND( AA, BB, CC, DD, FUN_I, X[ 12 ], 0x655b59c3, 6 );
			ROUND( DD, AA, BB, CC, FUN_I, X[ 3 ], 0x8f0ccc92, 10 );
			ROUND( CC, DD, AA, BB, FUN_I, X[ 10 ], 0xffeff47d, 15 );
			ROUND( BB, CC, DD, AA, FUN_I, X[ 1 ], 0x85845dd1, 21 );
			ROUND( AA, BB, CC, DD, FUN_I, X[ 8 ], 0x6fa87e4f, 6 );
			ROUND( DD, AA, BB, CC, FUN_I, X[ 15 ], 0xfe2ce6e0, 10 );
			ROUND( CC, DD, AA, BB, FUN_I, X[ 6 ], 0xa3014314, 15 );
			ROUND( BB, CC, DD, AA, FUN_I, X[ 13 ], 0x4e0811a1, 21 );
			ROUND( AA, BB, CC, DD, FUN_I, X[ 4 ], 0xf7537e82, 6 );
			ROUND( DD, AA, BB, CC, FUN_I, X[ 11 ], 0xbd3af235, 10 );
			ROUND( CC, DD, AA, BB, FUN_I, X[ 2 ], 0x2ad7d2bb, 15 );
			ROUND( BB, CC, DD, AA, FUN_I, X[ 9 ], 0xeb86d391, 21 );
		}
		
		ctx->A += AA;
		ctx->B += BB;
		ctx->C += CC;
		ctx->D += DD;
		
		size_t blockOffset = !bufferIsEmpty ? blockIndex : blockIndex + 1;
		block = curData + blockOffset * MD5_BLOCK_SIZE;
		blockIndex++;
	}
	while ( blockIndex < blocksCount );
	
	curData += blocksCount * MD5_BLOCK_SIZE;
	if ( !bufferIsEmpty ) {
		curData -= MD5_BLOCK_SIZE;
	}
	int newRemainSize; 
	if ( !bufferIsEmpty ) {
		newRemainSize = ( size - freeSpaceSize ) % MD5_BLOCK_SIZE; 
	}
	else {
		newRemainSize = size % MD5_BLOCK_SIZE;
	}
	if ( newRemainSize > 0 ) {
		memcpy( remainData, curData, newRemainSize );
	}
	ctx->remainSize = newRemainSize;
	
	return e_UpdateSuccess;
}

void MD5_Final( byte_t *outputHash, MD5_CTX *ctx )
{
	byte_t finitData[ MD5_BLOCK_SIZE * 2 ];
	byte_t zeroData[ MD5_BLOCK_SIZE ] = { 0 };
	int finitDataSize;
	ctx->remainData[ ctx->remainSize++ ] = 0x80;
	int remainSize = ctx->remainSize;
	if ( MD5_BLOCK_SIZE - remainSize >= DATA_LEN_SIZE )
	{
		finitDataSize = MD5_BLOCK_SIZE;
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
	dataLenData[ 0 ] = GET_BYTE( overallSize,  0 );
	dataLenData[ 1 ] = GET_BYTE( overallSize,  8 );
	dataLenData[ 2 ] = GET_BYTE( overallSize, 16 );
	dataLenData[ 3 ] = GET_BYTE( overallSize, 24 );
	dataLenData[ 4 ] = GET_BYTE( overallSize, 32 );
	dataLenData[ 5 ] = GET_BYTE( overallSize, 40 );
	dataLenData[ 6 ] = GET_BYTE( overallSize, 48 );
	dataLenData[ 7 ] = GET_BYTE( overallSize, 56 );
	ctx->remainSize = 0;
	MD5_Update( ctx, finitData, finitDataSize );
	MD5_GetHash( ctx, outputHash );
}

void MD5_GetRepr( char *hashRepr, const byte_t *hash )
{
	const static char reprSymbols[] = {
		'0', '1', '2', '3',
		'4', '5', '6', '7',
		'8', '9', 'a', 'b',
		'c', 'd', 'e', 'f'
	};
	int outputIndex = 0;
	for ( int byteIndex = 0; byteIndex < DIGEST_SIZE; byteIndex++ )
	{
		byte_t b = hash[ byteIndex ];
		hashRepr[ outputIndex ] = reprSymbols[ ( b >> 4 ) & 0x0F ];
		hashRepr[ outputIndex + 1 ] = reprSymbols[ b & 0x0F ];
		outputIndex += 2;
	}
}
