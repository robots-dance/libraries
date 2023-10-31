#include "utils.h"

uint16_t poly_div( uint16_t dividend, uint16_t divisor )
{
	uint16_t quotient = 0;
	bool finded = false;
	int bitIndex = SHORT_BITS - 1;
	while ( !finded && bitIndex >= 0 )
	{
		finded = ( 1 << bitIndex ) & divisor;
		bitIndex--;
	}
	int divisorDegree = bitIndex + 1;
	
	uint16_t curDividend = dividend;
	finded = true;
	while ( finded )
	{
		finded = false;
		for ( bitIndex = SHORT_BITS - 1; bitIndex >= divisorDegree;
			bitIndex-- )
		{
			if ( ( 1 << bitIndex ) & curDividend )
			{
				finded = true;
				byte_t quotientPart = bitIndex - divisorDegree;
				curDividend ^= divisor << quotientPart; 
				quotient |= 1 << quotientPart;
			}
		}
	}
	
	return quotient;
}

uint16_t poly_mul( uint16_t mult1, uint16_t mult2 )
{
	uint16_t result = 0;
	
	for ( int bitIndex = 0; bitIndex < SHORT_BITS; bitIndex++ )
	{
		if ( ( 1 << bitIndex ) & mult2 )
		{
			result ^= mult1 << bitIndex;
		}
	}
	
	return result;
}

byte_t gadd( byte_t b1, byte_t b2 )
{
	return b1 ^ b2;
}

byte_t gsub( byte_t b1, byte_t b2 )
{
	return b1 ^ b2;
}

byte_t gmul( byte_t b1, byte_t b2, uint16_t module, int degree )
{
	return gmod( poly_mul( b1, b2 ), module, degree );
}

byte_t gmod( uint16_t dividend, uint16_t divisor, int divisorDegree )
{
	bool finded = true;
	uint16_t result = dividend;
	while ( finded )
	{
		finded = false;
		for ( int bitIndex = SHORT_BITS - 1; bitIndex >= divisorDegree;
			bitIndex-- )
		{
			if ( ( 1 << bitIndex ) & result )
			{
				finded = true;
				byte_t quotient = bitIndex - divisorDegree;
				result ^= divisor << quotient;
			}
		}
	}
	return result;
}

void self_memcpy( byte_t *dst, const byte_t *src, size_t size )
{
	size_t byteIndex = 0;
	while ( byteIndex < size )
	{
		dst[ byteIndex ] = src[ byteIndex ];
		byteIndex++;
	}
}
