#include <stdio.h>
#include <string.h>
#include "aes_impl.h"

#define LINE_BUF_SIZE 32

#define USAGE_ERR 1
#define UNKNOWN_FUNCTION 2
#define CHECK_FAILED 3

#define CHECK_SUCCESS_MESS "\ncheck success\n"
#define CHECK_FAILED_MESS "\ncheck failed\n"

void PrintState( AesState );

int main( int argc, char **argv )
{
	if ( argc < 2 )
	{
		fprintf( stderr, "Usage: ./test-aes <func-name>\n" );
		return USAGE_ERR;
	}
	
	AesState state; 
	char lineBuf[ LINE_BUF_SIZE ] = { 0 };
	for ( int rowIndex = 0; rowIndex < STATE_SIZE; rowIndex++ )
	{
		fgets( lineBuf, LINE_BUF_SIZE, stdin );
		int b1, b2, b3, b4;
		
		sscanf( lineBuf, "%02x %02x %02x %02x", &b1, &b2, &b3, &b4 );
		state[ rowIndex ][ 0 ] = b1;
		state[ rowIndex ][ 1 ] = b2;
		state[ rowIndex ][ 2 ] = b3;
		state[ rowIndex ][ 3 ] = b4;
	}
	
	AesState oldState;
	memcpy( oldState, state, sizeof( AesState ) );
	
	const char *funcName = argv[ 1 ];
	bool isInverse = false;
	bool autocheckNeeded = false;
	if ( argc > 2 )
	{
		isInverse = !strcmp( argv[ 2 ], "inv" );
		autocheckNeeded = !strcmp( argv[ 2 ], "autocheck" );
	}
	if ( !strcmp( funcName, "subbytes" ) )
	{
		if ( !isInverse && !autocheckNeeded )
		{
			SubBytes( state );
			printf( "\nSubBytes:\n" );
			PrintState( state );
		}
		else if ( isInverse )
		{
			InvSubBytes( state );
			printf( "\nInvSubBytes:\n" );
			PrintState( state );
		}
		else // autocheckNeeded
		{
			SubBytes( state );
			InvSubBytes( state );
			if ( !memcmp( state, oldState, sizeof( AesState ) ) )
			{
				printf( CHECK_SUCCESS_MESS );
			}
			else
			{
				printf( CHECK_FAILED_MESS );
				return CHECK_FAILED;
			}
		}
	}
	else if ( !strcmp( funcName, "shiftrows" ) )
	{
		if ( !isInverse && !autocheckNeeded )
		{
			ShiftRows( state );
			printf( "\nShiftRows:\n" );
			PrintState( state );
		}
		else if ( isInverse )
		{
			InvShiftRows( state );
			printf( "\nInvShiftRows:\n" );
			PrintState( state );
		}
		else // autocheckNeeded
		{
			ShiftRows( state );
			InvShiftRows( state );
			if ( !memcmp( state, oldState, sizeof( AesState ) ) )
			{
				printf( CHECK_SUCCESS_MESS );
			}
			else
			{
				printf( CHECK_FAILED_MESS );
				return CHECK_FAILED;
			}
		}
	}
	else if ( !strcmp( funcName, "mixcolumns" ) )
	{
		if ( !isInverse && !autocheckNeeded )
		{
			MixColumns( state );
			printf( "\nMixColumns:\n" );
			PrintState( state );
		}
		else if ( isInverse )
		{
			InvMixColumns( state );
			printf( "\nInvMixColumns:\n" );
			PrintState( state );
		}
		else // autocheckNeeded
		{
			MixColumns( state );
			InvMixColumns( state );
			if ( !memcmp( state, oldState, sizeof( AesState ) ) )
			{
				printf( CHECK_SUCCESS_MESS );
			}
			else
			{
				printf( CHECK_FAILED_MESS );
				return CHECK_FAILED;
			}
		}
	}
	else
	{
		fprintf( stderr, "unknown function\n" );
		return UNKNOWN_FUNCTION;
	}
	
	return 0;
}

void PrintState( AesState state )
{
	for ( int rowIndex = 0; rowIndex < STATE_SIZE; rowIndex++ )
	{
		for ( int colIndex = 0; colIndex < STATE_SIZE; colIndex++ )
		{
			printf( "%02x ", state[ rowIndex ][ colIndex ] );
		}
		printf( "\n" );
	}
}
