#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha1.h"

#define USAGE_ERR 1
#define CANT_OPEN_FILE 2
#define CANT_ALLOC_MEM 3

#ifndef BLOCK_SIZE
#define BLOCK_SIZE ( 1024 * 8 ) // 8 Kb
#endif

int main( int argc, char **argv )
{
	if ( argc < 2 )
	{
		fprintf( stderr, "Usage: ./sha1sum <inp-file>\n" );
		return USAGE_ERR;
	}
	
	// open an input file
	FILE *inpFile = fopen( argv[ 1 ], "rb" );
	if ( NULL == inpFile )
	{
		fprintf( stderr, "can't open input file\n" );
		return CANT_OPEN_FILE;
	}
	
	// initialize an output hash
	SHA1_CTX ctxt;
	SHA1_Init( &ctxt );
	byte_t *block = ( byte_t* )malloc( BLOCK_SIZE );
	if ( NULL == block )
	{
		fclose( inpFile );
		fprintf( stderr, "can't allocate needed memory\n" );
		return CANT_ALLOC_MEM;
	}
	
	// calculate the hash
	bool isEnd = false;
	size_t readedCount = 0;
	while ( !isEnd )
	{
		readedCount = fread( block, 1, BLOCK_SIZE, inpFile );
		if ( readedCount > 0 )
		{
			SHA1_Update( &ctxt, block, readedCount );
		}
		else {
			isEnd = true;
		}
	}
	free( block );
	
	fclose( inpFile );
	
	// get a string representation of the calculated hash 
	byte_t hash[ 20 ];
	SHA1_Final( hash, &ctxt );
	for ( int byteIndex = 0; byteIndex < sizeof( hash ); byteIndex++ )
	{
		printf( "%02x", hash[ byteIndex ] );
	}
	printf( "\n" );
	
	return 0;
}

