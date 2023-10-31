#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

#define BAD_MUL_POLY_VALUE 1

#define BYTE_MAX 256
#define LINE_SIZE 8
#define MOD_POLY 0x11b

bool checkMulArg( int );

int main( int argc, char **argv )
{
	int mulPoly = 2;
	if ( argc > 1 )
	{
		mulPoly = atoi( argv[ 1 ] );
		if ( !checkMulArg( mulPoly ) )
		{
			fprintf( stderr, "incorrect mul poly value\n" );
			return BAD_MUL_POLY_VALUE;
		}
	}
	printf( "\t" );
	for ( int byteIndex = 0; byteIndex < BYTE_MAX; byteIndex++ )
	{
		printf( "0x%02x", gmul( byteIndex, mulPoly, MOD_POLY, 8 ) );
		if ( byteIndex != BYTE_MAX - 1 )
		{
			printf( "," );
			if ( ( byteIndex + 1 ) % LINE_SIZE == 0 )
			{
				printf( "\n\t" );
			}
			else
			{
				printf( " " );
			}
		}
	}
	return 0;
}

bool checkMulArg( int arg )
{
	if ( 2 == arg || 3 == arg )
	{
		return true; // MixColumns
	}
	if ( 9 == arg || 0xb == arg || 0xd == arg || 0xe == arg )
	{
		return true; // InvMixColumns
	}
	return false;
}
