#include <stdio.h>
#include <string.h>
#include "utils.h"

#define USAGE_ERR 1
#define BAD_CRYPT_OPER 2

#define GET_BIT( byte, bitIndex ) ( ( byte >> bitIndex ) & 1 )

#define TABLE_SIZE 16

#define IRRED_POLY ( ( uint16_t )0x11B ) // x ^ 8 + x ^ 4 + x ^ 3 + x + 1 

typedef byte_t SBoxTable[ TABLE_SIZE ][ TABLE_SIZE ];

void SubBytes( SBoxTable table );
void InvSubBytes( SBoxTable table );

byte_t affine( byte_t b );
byte_t inverse_affine( byte_t b );
byte_t inverse( byte_t b );

int main( int argc, char **argv )
{
	if ( argc < 2 )
	{
		fprintf( stderr, "Usage: ./calc-subbytes {encrypt|decrypt}\n" );
		return USAGE_ERR;
	}
	
	SBoxTable table = { 0 };
	
	char *cryptOperation = argv[ 1 ];
	if ( !strcmp( cryptOperation, "encrypt" ) )
	{
		SubBytes( table );
	}
	else if ( !strcmp( cryptOperation, "decrypt" ) )
	{
		InvSubBytes( table );
	}
	else
	{
		fprintf( stderr, "unknown crypt operation\n" );
		return BAD_CRYPT_OPER;
	}
	
	printf( "\t" );
	for ( int rowIndex = 0; rowIndex < TABLE_SIZE; rowIndex++ )
	{
		for ( int colIndex = 0; colIndex < TABLE_SIZE; colIndex++ )
		{
			printf( "0x%02x,", table[ rowIndex ][ colIndex ] );
			if ( ( colIndex + 1 ) % ( TABLE_SIZE / 2 ) != 0 )
			{
				printf( " " );
			}
			else {
				printf( "\n\t" );
			}
		}
	}
	
	return 0;
}

void SubBytes( SBoxTable table )
{
	for ( int rowIndex = 0; rowIndex < TABLE_SIZE; rowIndex++ )
	{
		for ( int colIndex = 0; colIndex < TABLE_SIZE; colIndex++ )
		{
			if ( 0 == rowIndex && 0 == colIndex )
			{
				continue;
			}
			byte_t b = rowIndex * TABLE_SIZE + colIndex;
			table[ rowIndex ][ colIndex ] = affine( inverse( b ) );
		}
	}
	table[ 0 ][ 0 ] = 0x63;
}

void InvSubBytes( SBoxTable table )
{
	for ( int rowIndex = 0; rowIndex < TABLE_SIZE; rowIndex++ )
	{
		for ( int colIndex = 0; colIndex < TABLE_SIZE; colIndex++ )
		{
			byte_t b = rowIndex * TABLE_SIZE + colIndex;
			table[ rowIndex ][ colIndex ] = inverse( inverse_affine( b ) );
		}
	}
}

byte_t affine( byte_t b )
{
	byte_t result = 0;
	for ( int bitIndex = 0; bitIndex < BYTE_BITS; bitIndex++ )
	{
		result |= ( GET_BIT( b, bitIndex ) ^
			GET_BIT( b, ( bitIndex + 4 ) % BYTE_BITS ) ^
			GET_BIT( b, ( bitIndex + 5 ) % BYTE_BITS ) ^
			GET_BIT( b, ( bitIndex + 6 ) % BYTE_BITS ) ^
			GET_BIT( b, ( bitIndex + 7 ) % BYTE_BITS ) ^
			GET_BIT( 0x63, bitIndex )
		) << bitIndex;
	}
	return result;
}

byte_t inverse_affine( byte_t b )
{
	byte_t result = 0;
	for ( int bitIndex = 0; bitIndex < BYTE_BITS; bitIndex++ )
	{
		result |= ( GET_BIT( b, ( bitIndex + 2 ) % BYTE_BITS ) ^
			GET_BIT( b, ( bitIndex + 5 ) % BYTE_BITS ) ^
			GET_BIT( b, ( bitIndex + 7 ) % BYTE_BITS ) ^
			GET_BIT( 0x05, 	bitIndex ) ) << bitIndex;
	}
	return result;
}

byte_t inverse( byte_t b )
{
	bool finded = false;
	int byteIndex = 0;
	while ( !finded && byteIndex <= 255 )
	{
		if ( gmul( byteIndex, b, IRRED_POLY, 8 ) == 1 )
		{
			finded = true;
		}
		byteIndex++;
	}
	return byteIndex - 1;
}
