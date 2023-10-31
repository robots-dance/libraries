#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha512.h"

// error codes
#define USAGE_ERR 1
#define CANT_OPEN_FILE 2
#define CANT_ALLOC_MEM 3
#define BAD_DIGEST_SIZE 4
#define INIT_FAILED 5

#ifndef BLOCK_SIZE
#define BLOCK_SIZE ( 1024 * 8 ) // 8 Kb
#endif
#define DEF_DIGEST_SIZE 512 // in bits

int main( int argc, char **argv )
{
	if ( argc < 2 )
	{
		fprintf( stderr, "Usage: ./sha512sum <inp-file> [<dig-size>]\n" );
		return USAGE_ERR;
	}
	
	// check a digest size
	int digestSize = DEF_DIGEST_SIZE;
	if ( argc > 2 )
	{
		digestSize = atoi( argv[ 2 ] );
		if ( digestSize <= 0 || digestSize > 512 )
		{
			fprintf( stderr, "incorrect digest size: "
				"it must be in [ 1; 512 ]\n" );
			return BAD_DIGEST_SIZE;
		}
	}
	
	// initialize an output hash
	SHA512_CTX ctxt;
	if ( 384 == digestSize )
	{
		SHA384_Init( &ctxt );
	}
	else if ( 512 == digestSize )
	{
		SHA512_Init( &ctxt );
	}
	else
	{
		if ( !SHA512t_Init( &ctxt, digestSize ) )
		{
			fprintf( stderr, "initialization failed\n" );
			return INIT_FAILED;
		}
	}
	
	// open an input file
	FILE *inpFile = fopen( argv[ 1 ], "rb" );
	if ( NULL == inpFile )
	{
		fprintf( stderr, "can't open input file\n" );
		return CANT_OPEN_FILE;
	}
	
	// try to allocate a needed memory
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
			SHA512_Update( &ctxt, block, readedCount );
		}
		else {
			isEnd = true;
		}
	}
	free( block );
	
	fclose( inpFile );
	
	// get a string representation of the calculated hash
	byte_t hash[ 64 ];
	SHA512_Final( hash, &ctxt );
	for ( int byteIndex = 0; byteIndex < digestSize / 8; byteIndex++ )
	{
		printf( "%02x", hash[ byteIndex ] );
	}
	printf( "\n" );
	
	return 0;
}
