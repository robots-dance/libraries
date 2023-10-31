#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

 #define BLOCK_SIZE ( 1024 * 8 ) // 8 Kb

int main( int argc, char **argv )
{
	if ( argc < 2 )
	{
		fprintf( stderr, "Usage: ./md5sum <inp-file>\n" );
		return 1;
	}
	
	FILE *inpFile = fopen( argv[ 1 ], "rb" );
	if ( NULL == inpFile )
	{
		fprintf( stderr, "can't open input file\n" );
		return 2;
	}
	
	MD5_CTX ctxt;
	MD5_Init( &ctxt );
	byte_t *block = ( byte_t* )malloc( BLOCK_SIZE );
	if ( NULL == block )
	{
		fprintf( stderr, "can't allocate needed memory\n" );
		return 3;
	}
	
	bool isEnd = false;
	INT64 processedCount = 0;
	int readedCount = 0;
	while ( !isEnd )
	{
		readedCount = fread( block, 1, BLOCK_SIZE, inpFile );
		if ( readedCount > 0 )
		{
			processedCount += readedCount;
			MD5_Update( &ctxt, block, readedCount );
		}
		else {
			isEnd = true;
		}
	}
	free( block );
	
	byte_t hash[ 16 ];
	MD5_Final( hash, &ctxt );
	for ( int byteIndex = 0; byteIndex < sizeof( hash ); byteIndex++ )
	{
		printf( "%02x", hash[ byteIndex ] );
	}
	printf( "\n" );
	
	return 0;
}

