#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#define BAD_USAGE 1
#define BAD_COUNT_VALUE 2
#define BAD_LINE_SIZE_VALUE 3
#define CANT_ALLOC_MEM 4
#define RAND_ERROR_OCCURED 5
#define BAD_OPTION 6

typedef unsigned char byte_t;

void PrintBytes( byte_t *bytes, int count, int lineSize, bool spacesNeeded );


int main( int argc, char **argv )
{
	if ( argc < 3 )
	{
		fprintf( stderr, "Usage: ./genbytes <count> "
			"<line-size> [--no-spaces]\n" );
		return BAD_USAGE;
	}
	
	int count = atoi( argv[ 1 ] );
	if ( count <= 0 )
	{
		fprintf( stderr, "incorrect count value\n" );
		return BAD_COUNT_VALUE;
	}
	
	int lineSize = atoi( argv[ 2 ] );
	if ( lineSize <= 0 )
	{
		fprintf( stderr, "incorrect line size value\n" );
		return BAD_LINE_SIZE_VALUE;
	}
	
	bool spacesNeeded = true;
	if ( argc > 3 )
	{
		if ( !strcmp( argv[ 3 ], "--no-spaces" ) )
		{
			spacesNeeded = false;
		}
		else
		{
			fprintf( stderr, "incorrect option name\n" );
			return BAD_OPTION;
		}
	}
	
	byte_t *bytes = ( byte_t * )malloc( count );
	if ( NULL == bytes )
	{
		fprintf( stderr, "can't allocate needed memory\n" );
		return CANT_ALLOC_MEM;
	}
	
	if ( !RAND_bytes( bytes, count ) )
	{
		free( bytes );
		fprintf( stderr, "error occured during a data generation\n" );
		return RAND_ERROR_OCCURED; 
	}
	else
	{
		PrintBytes( bytes, count, lineSize, spacesNeeded );
	}
	
	return 0;
}

void PrintBytes( byte_t *bytes, int count, int lineSize, bool spacesNeeded )
{
	int remainCount = count % lineSize; 
	int rowsCount = count / lineSize + ( remainCount > 0 ? 1 : 0 );
	for ( int rowIndex = 0; rowIndex < rowsCount; rowIndex++ )
	{
		int curLineSize = lineSize;
		if ( rowIndex == rowsCount - 1 && remainCount > 0 )
		{
			curLineSize = remainCount;
		}
		for ( int colIndex = 0; colIndex < curLineSize; colIndex++ )
		{
			printf( "%02x", bytes[ rowIndex * lineSize + colIndex ] );
			if ( colIndex != curLineSize - 1 )
			{
				if ( spacesNeeded )
				{
					printf( " " );
				}
			}
			else {
				printf( "\n" );
			}
		}
	}
}
