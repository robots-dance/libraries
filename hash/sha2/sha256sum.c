#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"

#define USAGE_ERR 1
#define CANT_OPEN_FILE 2
#define CANT_ALLOC_MEM 3
#define BAD_DIGEST_SIZE 4

#ifndef BLOCK_SIZE
#define BLOCK_SIZE ( 1024 * 8 ) // 8 Kb
#endif
#define DEF_DIGEST_SIZE 256 // in bits

int main( int argc, char **argv )
{
	if ( argc < 2 )
	{
		fprintf( stderr, "Usage: ./sha256sum <inp-file> [<dig-size>]\n" );
		return USAGE_ERR;
	}
	
	// open an input file
	FILE *inpFile = fopen( argv[ 1 ], "rb" );
	if ( NULL == inpFile )
	{
		fprintf( stderr, "can't open input file\n" );
		return CANT_OPEN_FILE;
	}
	
	int digestSize = DEF_DIGEST_SIZE;
	if ( argc > 2 )
	{
		digestSize = atoi( argv[ 2 ] );
		if ( digestSize != 224 && digestSize != 256 )
		{
			fclose( inpFile );
			fprintf( stderr, "incorrect digest size: "
				"allowed 224, 256 values\n" );
			return BAD_DIGEST_SIZE;
		}
	}
	
	// initialize an output hash
	SHA256_CTX ctxt;
	if ( 224 == digestSize )
	{
		SHA224_Init( &ctxt );
	}
	else {
		SHA256_Init( &ctxt );
	}
	byte_t *block = ( byte_t* )malloc( BLOCK_SIZE );
	if ( NULL == block )
	{
		fclose( inpFile );
		fprintf( stderr, "can't allocate memory\n" );
		return CANT_ALLOC_MEM;
	}
	
	// calculate the hash
	bool isEnd = false;
	while ( !isEnd )
	{
		size_t readedCount = fread( block, 1, BLOCK_SIZE, inpFile );
		if ( readedCount > 0 )
		{
			SHA256_Update( &ctxt, block, readedCount );
		}
		else {
			isEnd = true;
		}
	}
	free( block );
	
	fclose( inpFile );
	
	// get a string representation of the calculated hash
	byte_t hash[ 32 ];
	SHA256_Final( hash, &ctxt );
	for ( int byteIndex = 0; byteIndex < digestSize / 8; byteIndex++ )
	{
		printf( "%02x", hash[ byteIndex ] );
	}
	printf( "\n" );
	
	return 0;
}
