#include <string.h>
#include "sha512.h"

#define DATA_LEN_SIZE 16

#define W_ARR_SIZE 80

#define K0  0x428a2f98d728ae22
#define K1  0x7137449123ef65cd
#define K2  0xb5c0fbcfec4d3b2f
#define K3  0xe9b5dba58189dbbc
#define K4  0x3956c25bf348b538
#define K5  0x59f111f1b605d019
#define K6  0x923f82a4af194f9b
#define K7  0xab1c5ed5da6d8118
#define K8  0xd807aa98a3030242
#define K9  0x12835b0145706fbe
#define K10 0x243185be4ee4b28c
#define K11 0x550c7dc3d5ffb4e2
#define K12 0x72be5d74f27b896f
#define K13 0x80deb1fe3b1696b1
#define K14 0x9bdc06a725c71235
#define K15 0xc19bf174cf692694
#define K16 0xe49b69c19ef14ad2
#define K17 0xefbe4786384f25e3
#define K18 0xfc19dc68b8cd5b5
#define K19 0x240ca1cc77ac9c65
#define K20 0x2de92c6f592b0275
#define K21 0x4a7484aa6ea6e483
#define K22 0x5cb0a9dcbd41fbd4
#define K23 0x76f988da831153b5
#define K24 0x983e5152ee66dfab
#define K25 0xa831c66d2db43210
#define K26 0xb00327c898fb213f
#define K27 0xbf597fc7beef0ee4
#define K28 0xc6e00bf33da88fc2
#define K29 0xd5a79147930aa725
#define K30 0x6ca6351e003826f
#define K31 0x142929670a0e6e70
#define K32 0x27b70a8546d22ffc
#define K33 0x2e1b21385c26c926
#define K34 0x4d2c6dfc5ac42aed
#define K35 0x53380d139d95b3df
#define K36 0x650a73548baf63de
#define K37 0x766a0abb3c77b2a8
#define K38 0x81c2c92e47edaee6
#define K39 0x92722c851482353b
#define K40 0xa2bfe8a14cf10364
#define K41 0xa81a664bbc423001
#define K42 0xc24b8b70d0f89791
#define K43 0xc76c51a30654be30
#define K44 0xd192e819d6ef5218
#define K45 0xd69906245565a910
#define K46 0xf40e35855771202a
#define K47 0x106aa07032bbd1b8
#define K48 0x19a4c116b8d2d0c8
#define K49 0x1e376c085141ab53
#define K50 0x2748774cdf8eeb99
#define K51 0x34b0bcb5e19b48a8
#define K52 0x391c0cb3c5c95a63
#define K53 0x4ed8aa4ae3418acb
#define K54 0x5b9cca4f7763e373
#define K55 0x682e6ff3d6b2b8a3
#define K56 0x748f82ee5defb2fc
#define K57 0x78a5636f43172f60
#define K58 0x84c87814a1f0ab72
#define K59 0x8cc702081a6439ec
#define K60 0x90befffa23631e28
#define K61 0xa4506cebde82bde9
#define K62 0xbef9a3f7b2c67915
#define K63 0xc67178f2e372532b
#define K64 0xca273eceea26619c
#define K65 0xd186b8c721c0c207
#define K66 0xeada7dd6cde0eb1e
#define K67 0xf57d4f7fee6ed178
#define K68 0x6f067aa72176fba
#define K69 0xa637dc5a2c898a6
#define K70 0x113f9804bef90dae
#define K71 0x1b710b35131c471b
#define K72 0x28db77f523047d84
#define K73 0x32caab7b40c72493
#define K74 0x3c9ebe0a15c9bebc
#define K75 0x431d67c49c100d4c
#define K76 0x4cc5d4becb3e42b6
#define K77 0x597f299cfc657e2a
#define K78 0x5fcb6fab3ad6faec
#define K79 0x6c44198c4a475817

#define Ch( X, Y, Z ) ( ( X & Y ) ^ ( ~X & Z ) )
#define Maj( X, Y, Z ) ( ( X & Y ) ^ ( X & Z ) ^ ( Y & Z ) )

#define ROTR( x, n ) ( ( x >> n ) | ( x << ( 64 - n ) ) )

#define SIGMA0( x ) ( ROTR( x, 28 ) ^ ROTR( x, 34 ) ^ ROTR( x, 39 ) )
#define SIGMA1( x ) ( ROTR( x, 14 ) ^ ROTR( x, 18 ) ^ ROTR( x, 41 ) ) 
#define sigma0( x ) ( ROTR( x, 1 ) ^ ROTR( x, 8 ) ^ ( ( x ) >> 7 ) )
#define sigma1( x ) ( ROTR( x, 19 ) ^ ROTR( x, 61 ) ^ ( ( x ) >> 6 ) )

#define ROUND( W, K ) do { \
	UINT64 T1 = H + SIGMA1( E ) + Ch( E, F, G ) + K + W; \
	UINT64 T2 = SIGMA0( A ) + Maj( A, B, C ); \
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

void add_to_int128( INT128 *number, size_t value )
{
	if ( ( UINT64_MAX - number->low ) < value )
	{
		number->high++;
	}
	number->low += value;
}

void set_int128_val( INT128 *number, UINT64 value )
{
	number->high = 0;
	number->low = value;
}

void mov_uint64_to_mem( byte_t *output, UINT64 value )
{
	output[ 0 ] = GET_BYTE( value, 56 );
	output[ 1 ] = GET_BYTE( value, 48 );
	output[ 2 ] = GET_BYTE( value, 40 );
	output[ 3 ] = GET_BYTE( value, 32 );
	output[ 4 ] = GET_BYTE( value, 24 );
	output[ 5 ] = GET_BYTE( value, 16 );
	output[ 6 ] = GET_BYTE( value, 8 );
	output[ 7 ] = GET_BYTE( value, 0 );
}

void get_hash_part( UINT64 *registers, int regsCount, byte_t *output )
{
	int curByteIndex = 0;
	for ( int regIndex = 0; regIndex < regsCount; regIndex++ )
	{
		UINT64 reg = registers[ regIndex ];
		mov_uint64_to_mem( output + curByteIndex, reg );
		curByteIndex += sizeof( UINT64 );
	}
}

void SHA384_GetHash( SHA512_CTX *ctx, byte_t *output )
{
	UINT64 registers[ 6 ] = {
		ctx->A, ctx->B, ctx->C,
		ctx->D, ctx->E, ctx->F
	};
	get_hash_part( registers, 6, output );
}

void SHA512_GetHash( SHA512_CTX *ctx, byte_t *output )
{
	UINT64 registers[ 8 ] = {
		ctx->A, ctx->B, ctx->C, ctx->D,
		ctx->E, ctx->F, ctx->G, ctx->H
	};
	get_hash_part( registers, 8, output );
}

void SHA512t_GetHash( SHA512_CTX *ctx, byte_t *output )
{
	UINT64 registers[ 8 ] = {
		ctx->A, ctx->B, ctx->C, ctx->D,
		ctx->E, ctx->F, ctx->G, ctx->H
	};
	int digestSize = ctx->digestSize / BYTE_BITS; 
	int regsCount = digestSize / sizeof( UINT64 );
	get_hash_part( registers, regsCount, output );
	int remainsCount = digestSize % sizeof( UINT64 );
	if ( remainsCount > 0 )
	{
		UINT64 nextReg = registers[ regsCount ];
		int outputByteIndex = regsCount * sizeof( UINT64 );
		for ( int remainsByteIndex = 0; remainsByteIndex < remainsCount;
			remainsByteIndex++ )
		{
			output[ outputByteIndex++ ] = ( byte_t ) ( nextReg >> ( 56 -
				BYTE_BITS * remainsByteIndex ) );
		}
	}
}

void SHA384_Init( SHA512_CTX *ctx )
{
	ctx->A = 0xcbbb9d5dc1059ed8;
	ctx->B = 0x629a292a367cd507;
	ctx->C = 0x9159015a3070dd17;
	ctx->D = 0x152fecd8f70e5939;
	ctx->E = 0x67332667ffc00b31;
	ctx->F = 0x8eb44a8768581511;
	ctx->G = 0xdb0c2e0d64f98fa7;
	ctx->H = 0x47b5481dbefa4fa4;
	set_int128_val( &ctx->overallSize, 0 );
	ctx->remainSize = 0;
	ctx->digestSize = 384;
}

void SHA512_Init( SHA512_CTX *ctx )
{
	ctx->A = 0x6a09e667f3bcc908;
	ctx->B = 0xbb67ae8584caa73b;
	ctx->C = 0x3c6ef372fe94f82b;
	ctx->D = 0xa54ff53a5f1d36f1;
	ctx->E = 0x510e527fade682d1;
	ctx->F = 0x9b05688c2b3e6c1f;
	ctx->G = 0x1f83d9abfb41bd6b;
	ctx->H = 0x5be0cd19137e2179;
	set_int128_val( &ctx->overallSize, 0 );
	ctx->remainSize = 0;
	ctx->digestSize = 512;
}

bool SHA512t_Init( SHA512_CTX *ctx, int digestSize )
{
	if ( 224 == digestSize )
	{
		ctx->A = 0x8C3D37C819544DA2;
		ctx->B = 0x73E1996689DCD4D6;
		ctx->C = 0x1DFAB7AE32FF9C82;
		ctx->D = 0x679DD514582F9FCF;
		ctx->E = 0x0F6D2B697BD44DA8;
		ctx->F = 0x77E36F7304C48942;
		ctx->G = 0x3F9D85A86A1D36C8;
		ctx->H = 0x1112E6AD91D692A1;
	}
	else if ( 256 == digestSize )
	{
		ctx->A = 0x22312194FC2BF72C;
		ctx->B = 0x9F555FA3C84C64C2;
		ctx->C = 0x2393B86B6F53B151;
		ctx->D = 0x963877195940EABD;
		ctx->E = 0x96283EE2A88EFFE3;
		ctx->F = 0xBE5E1E2553863992;
		ctx->G = 0x2B0199FC2C85B8AA;
		ctx->H = 0x0EB72DDC81C52CA2;
	}
	else
	{
		// no implemented now
		return false;
	}
	set_int128_val( &ctx->overallSize, 0 );
	ctx->remainSize = 0;
	ctx->digestSize = digestSize;
	return true;
}

UpdateState SHA512_Update( SHA512_CTX *ctx, const byte_t *data,
	size_t size )
{
	if ( NULL == data || 0 == size )
	{
		return e_BadParams;
	}
	add_to_int128( &ctx->overallSize, size );
	int remainSize = ctx->remainSize;
	int freeSpaceSize = SHA512_BLOCK_SIZE - remainSize;
	byte_t bufferIsEmpty = SHA512_BLOCK_SIZE == freeSpaceSize ? 1 : 0;
	byte_t *remainData = ctx->remainData;
	byte_t *curData = ( byte_t* )data; 
	if ( size < freeSpaceSize )
	{
		memcpy( remainData + remainSize, curData, size );
		ctx->remainSize += size;
		return e_NoBufferFilled;
	}
	else
	{
		memcpy( remainData + remainSize, curData, freeSpaceSize );
	}
	
	size_t blocksCount = ( size - freeSpaceSize ) / SHA512_BLOCK_SIZE + 1;
	if ( !bufferIsEmpty ) {
		curData += freeSpaceSize;
	}
	
	size_t blockIndex = 0;
	byte_t *block = !bufferIsEmpty ? remainData : curData; 
	
	UINT64 W[ W_ARR_SIZE ];
	
	do
	{
		UINT64 A = ctx->A; 
		UINT64 B = ctx->B;
		UINT64 C = ctx->C;
		UINT64 D = ctx->D;
		UINT64 E = ctx->E;
		UINT64 F = ctx->F;
		UINT64 G = ctx->G;
		UINT64 H = ctx->H;
		
		for ( int wordIndex = 0; wordIndex < 16; wordIndex++ )
		{
			UINT wordOffset = wordIndex * sizeof( UINT64 ); 
			W[ wordIndex ] = (
				( ( UINT64 )block[ wordOffset ] << 56 ) |
				( ( UINT64 )block[ wordOffset + 1 ] << 48 ) |
				( ( UINT64 )block[ wordOffset + 2 ] << 40 ) |
				( ( UINT64 )block[ wordOffset + 3 ] << 32 ) |
				( ( UINT64 )block[ wordOffset + 4 ] << 24 ) |
				( ( UINT64 )block[ wordOffset + 5 ] << 16 ) |
				( ( UINT64 )block[ wordOffset + 6 ] <<  8 ) |
				( ( UINT64 )block[ wordOffset + 7 ] ) );
		}
		
		for ( int wordIndex = 16; wordIndex < W_ARR_SIZE; wordIndex++ )
		{
			UINT64 arg0 = W[ wordIndex - 2 ];
			UINT64 arg1 = W[ wordIndex - 15 ];
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
		ROUND( W[ 64 ], K64 );
		ROUND( W[ 65 ], K65 );
		ROUND( W[ 66 ], K66 );
		ROUND( W[ 67 ], K67 );
		ROUND( W[ 68 ], K68 );
		ROUND( W[ 69 ], K69 );
		ROUND( W[ 70 ], K70 );
		ROUND( W[ 71 ], K71 );
		ROUND( W[ 72 ], K72 );
		ROUND( W[ 73 ], K73 );
		ROUND( W[ 74 ], K74 );
		ROUND( W[ 75 ], K75 );
		ROUND( W[ 76 ], K76 );
		ROUND( W[ 77 ], K77 );
		ROUND( W[ 78 ], K78 );
		ROUND( W[ 79 ], K79 );
		
		ctx->A += A;
		ctx->B += B;
		ctx->C += C;
		ctx->D += D;
		ctx->E += E;
		ctx->F += F;
		ctx->G += G;
		ctx->H += H;
		
		size_t blockOffset = !bufferIsEmpty ? blockIndex : blockIndex + 1;
		block = curData + blockOffset * SHA512_BLOCK_SIZE;
		blockIndex++;
	}
	while ( blockIndex < blocksCount );
	
	curData += blocksCount * SHA512_BLOCK_SIZE;
	if ( !bufferIsEmpty )
	{
		curData -= SHA512_BLOCK_SIZE;
	}
	
	int newRemainSize;
	if ( !bufferIsEmpty )
	{
		newRemainSize += ( size - freeSpaceSize ) % SHA512_BLOCK_SIZE; 
	}
	else {
		newRemainSize = size % SHA512_BLOCK_SIZE; 
	}
	if ( newRemainSize > 0 ) {
		memcpy( remainData, curData, newRemainSize );
	}
	ctx->remainSize = newRemainSize;
	
	return e_UpdateSuccess;
}

void SHA512_Final( byte_t *outputHash, SHA512_CTX *ctx )
{
	byte_t finitData[ SHA512_BLOCK_SIZE  * 2 ];
	byte_t zeroData[ SHA512_BLOCK_SIZE ] = { 0 };
	
	int finitDataSize;
	ctx->remainData[ ctx->remainSize++ ] = 0x80;
	int remainSize = ctx->remainSize;
	if ( SHA512_BLOCK_SIZE - remainSize >= DATA_LEN_SIZE )
	{
		finitDataSize = SHA512_BLOCK_SIZE;
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
	INT128 overallSize = ctx->overallSize;
	
	// overallSize *= 8
	byte_t highBits = ( overallSize.low >> ( 63 - 3 ) ) & 3;
	overallSize.low <<= 3;
	overallSize.high <<= 3;
	overallSize.high |= highBits;
	
	mov_uint64_to_mem( dataLenData, ( UINT64 )overallSize.high );
	mov_uint64_to_mem( dataLenData + sizeof( UINT64 ), overallSize.low );
	ctx->remainSize = 0;
	
	int digestSize = ctx->digestSize;
	SHA512_Update( ctx, finitData, finitDataSize );	
	if ( 384 == digestSize )
	{
		SHA384_GetHash( ctx, outputHash );
	}
	else if ( 512 == digestSize )
	{
		SHA512_GetHash( ctx, outputHash );
	}
	else
	{
		SHA512t_GetHash( ctx, outputHash );
	}
}
