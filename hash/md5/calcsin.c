#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define MAX_INT 4294967296

int main( int argc, char **argv )
{
	printf( "static unsigned int T[ 65 ] = {\n" );
	printf( "\t0,\n" );
	for ( int i = 1; i <= 64; i++ )
	{
		double val = MAX_INT * sin( i );
		if ( val < 0 ) {
			val *= -1;
		}
		unsigned long ival = val;
		printf( "\t0x%x,\n", ival );
	}
	printf( "}\n" );
	return 0;
}
