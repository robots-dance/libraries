#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef USE_OPENSSL
#include <openssl/evp.h>
#endif

#include "aes.h"

// error codes
#define BAD_USAGE 1
#define CANT_OPEN_INPUT_FILE 2
#define CANT_OPEN_OUTPUT_FILE 3
#define BAD_KEY_FORMAT 4
#define BAD_IV_FORMAT 5
#define BAD_ALG_MODE 6
#define BAD_OPTION_SELECTED 7
#define OPERATION_FAILED 8

// #define READ_BLOCK_SIZE ( 1048576 * 1024 )
#define READ_BLOCK_SIZE ( 12 * 1024 )


// parse functions
bool ParseHexKey( const char *key, byte_t *binKey, int *keySize );
bool ParseInitVector( const char *iv, byte_t *binIV );
bool ParseAlgMode( const char *mode, CryptMode *numMode );

// crypt functions

#ifdef USE_OPENSSL
typedef const EVP_CIPHER *( *OpenSSLCipher )( void );

const EVP_CIPHER *GetCipher( int keySize, CryptMode mode );
#endif

bool EncryptFile( FILE *inpFile, FILE *outFile,
	byte_t *key, int keySize,
	byte_t *iv, CryptMode mode,
	long *time );

bool DecryptFile( FILE *inpFile, FILE *outFile,
	byte_t *key, int keySize,
	byte_t *iv, CryptMode mode,
	long *time );

void CloseFiles( FILE *, FILE * );


int main( int argc, char **argv )
{
	if ( argc < 6 )
	{
		fprintf( stderr, "Usage: ./encryptor <inp-path> "
			"<out-path> <key> <iv> <mode> [-enc|-dec]\n" );
		return BAD_USAGE;
	}
	
	byte_t key[ MAX_KEY_SIZE ];
	int keySize;
	if ( !ParseHexKey( argv[ 3 ], key, &keySize ) )
	{
		fprintf( stderr, "incorrect raw key format\n" );
		return BAD_KEY_FORMAT;
	}
	
	byte_t iv[ IV_SIZE ];
	if ( !ParseInitVector( argv[ 4 ], iv ) )
	{
		fprintf( stderr, "incorrect init vector\n" );
		return BAD_IV_FORMAT;
	}
	
	CryptMode mode;
	if ( !ParseAlgMode( argv[ 5 ], &mode ) )
	{
		fprintf( stderr, "incorrect algorithm mode\n" );
		return BAD_ALG_MODE;
	}
	
	bool encryptionEnabled = true;
	if ( argc > 6 )
	{
		const char *option = argv[ 6 ];
		if ( !strcmp( option, "-dec" ) )
		{
			encryptionEnabled = false;
		}
		else if ( strcmp( option, "-enc" ) != 0 )
		{
			fprintf( stderr, "incorrect option specified\n" );
			return BAD_OPTION_SELECTED;
		}
	}
	
	FILE *inpFile = fopen( argv[ 1 ], "rb" );
	FILE *outFile = fopen( argv[ 2 ], "wb" );
	if ( NULL == inpFile || NULL == outFile )
	{
		int errorCode = 0;
		
		if ( NULL == inpFile )
		{
			fprintf( stderr, "can't open input file\n" );
			errorCode = CANT_OPEN_INPUT_FILE;
		}
		else
		{
			fprintf( stderr, "can't open output file\n" );
			errorCode = CANT_OPEN_OUTPUT_FILE;
		}
		
		CloseFiles( inpFile, outFile );
		
		return errorCode;
	}
	
	bool error = false;
	long execTime = 0;
	if ( encryptionEnabled )
	{
		error = !EncryptFile( inpFile, outFile, key,
			keySize, iv, mode, &execTime );
	}
	else
	{
		error = !DecryptFile( inpFile, outFile, key,
			keySize, iv, mode, &execTime );
	}
	
	if ( error )
	{
		fprintf( stderr, "error occured during an operation\n" );
	}
	else
	{
		printf( "time of operation: %d sec\n", execTime );
	}
	
	CloseFiles( inpFile, outFile );
	
	return !error ? 0 : OPERATION_FAILED;
}

// parse functions
bool ParseHexKey( const char *key, byte_t *binKey, int *binKeySize )
{
	size_t keylen = strlen( key );
	if ( 0 == keylen || keylen % 2 > 0 )
	{
		return false;
	}
	
	size_t bytesCount = keylen / 2;
	size_t keySize = bytesCount * 8; 
	if ( keySize != 128 && keySize != 192 && keySize != 256 )
	{
		return false;
	}
	
	byte_t output[ MAX_KEY_SIZE ];
	for ( int byteIndex = 0; byteIndex < bytesCount; byteIndex++ )
	{
		if ( sscanf( key + byteIndex * 2, "%02x", &output[ byteIndex ] ) != 1 )
		{
			return false;
		}
	}
	self_memcpy( binKey, output, bytesCount );
	*binKeySize = keySize;
	
	return true;
}

bool ParseInitVector( const char *iv, byte_t *binIV )
{
	size_t ivlen = strlen( iv );
	if ( 0 == ivlen || ivlen % 2 > 0 )
	{
		return false;
	}
	
	if ( ivlen / 2 != IV_SIZE )
	{
		return false;
	}
	
	byte_t output[ IV_SIZE ];
	for ( int byteIndex = 0; byteIndex < sizeof( output ); byteIndex++ )
	{
		if ( sscanf( iv + byteIndex * 2, "%02x", &output[ byteIndex ] ) != 1 )
		{
			return false;
		}
	}
	self_memcpy( binIV, output, sizeof( output ) );
	
	return true;
}

bool ParseAlgMode( const char *mode, CryptMode *numMode )
{
	static const char *textModes[] = {
		"cbc", "cfb", "ecb", "ofb"
	};
	CryptMode output = e_CBC;
	while ( output < e_InvalidMode )
	{
		if ( !strcmp( mode, textModes[ output ] ) )
		{
			*numMode = output;
			return true;
		}
		output++;
	}
	return false;
}
// ----

// crypt functions
#ifdef USE_OPENSSL
const EVP_CIPHER *GetCipher( int keySize, CryptMode mode )
{
	static OpenSSLCipher ciphers[ 3 ][ e_InvalidMode ] = {
		{ EVP_aes_128_cbc, EVP_aes_128_cfb, EVP_aes_128_ecb, EVP_aes_128_ofb },
		{ EVP_aes_192_cbc, EVP_aes_192_cfb, EVP_aes_192_ecb, EVP_aes_192_ofb },
		{ EVP_aes_256_cbc, EVP_aes_256_cfb, EVP_aes_256_ecb, EVP_aes_256_ofb }
	};
	return ciphers[ keySize / 64 - 2 ][ mode ]();
}
#endif

bool EncryptFile( FILE *inpFile, FILE *outFile,
	byte_t *key, int keySize,
	byte_t *iv, CryptMode mode,
	long *time )
{
	#ifdef USE_OPENSSL
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init( &ctx );
	EVP_EncryptInit_ex( &ctx, GetCipher( keySize, mode ), 0, key, iv );
	#else
	AES_CTX ctx;
	AES_EncryptInit( &ctx, keySize, key, iv, mode );
	#endif
	
	byte_t *inpBuff = ( byte_t* )malloc( READ_BLOCK_SIZE );
	byte_t *outBuff = ( byte_t* )malloc( READ_BLOCK_SIZE );
	if ( NULL == inpBuff || NULL == outBuff )
	{
		return false;
	}
	
	size_t toWriteSize;
	long int prevPos = 0;
	while ( !feof( inpFile ) )
	{
		fread( inpBuff, READ_BLOCK_SIZE, 1, inpFile );
		size_t readedCount = ftell( inpFile ) - prevPos;
		prevPos = ftell( inpFile );
		clock_t prevTime = clock();
		#ifdef USE_OPENSSL
		toWriteSize = 0;
		if ( !EVP_EncryptUpdate( &ctx, outBuff, ( int* )&toWriteSize,
			inpBuff, readedCount ) )
		{
			return false;
		}
		#else
		AES_EncryptUpdate( &ctx, inpBuff, readedCount, outBuff, &toWriteSize );
		#endif
		*time += ( clock() - prevTime ) / CLOCKS_PER_SEC;
		
		if ( toWriteSize > 0 )
		{
			fwrite( outBuff, toWriteSize, 1, outFile );
		}
	}
	
	#ifdef USE_OPENSSL
	toWriteSize = 0;
	if ( !EVP_EncryptFinal_ex( &ctx, outBuff, ( int* )&toWriteSize ) )
	{
		return false;
	}
	EVP_CIPHER_CTX_cleanup( &ctx );
	#else
	AES_EncryptFinal( &ctx, outBuff, &toWriteSize );
	#endif
	
	if ( toWriteSize > 0 )
	{
		fwrite( outBuff, toWriteSize, 1, outFile );
	}
	
	return true;
}

bool DecryptFile( FILE *inpFile, FILE *outFile,
	byte_t *key, int keySize,
	byte_t *iv, CryptMode mode,
	long *time )
{
	#ifdef USE_OPENSSL
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init( &ctx );
	EVP_DecryptInit_ex( &ctx, GetCipher( keySize, mode ), 0, key, iv );
	#else
	AES_CTX ctx;
	AES_DecryptInit( &ctx, keySize, key, iv, mode );
	#endif
	
	byte_t *inpBuff = ( byte_t* )malloc( READ_BLOCK_SIZE );
	byte_t *outBuff = ( byte_t* )malloc( READ_BLOCK_SIZE );
	if ( NULL == inpBuff || NULL == outBuff )
	{
		return false;
	}
	
	size_t toWriteSize;
	long int prevPos = 0;
	while ( !feof( inpFile ) )
	{
		fread( inpBuff, READ_BLOCK_SIZE, 1, inpFile );
		size_t readedCount = ftell( inpFile ) - prevPos;
		prevPos = ftell( inpFile );
		clock_t prevTime = clock();
		#ifdef USE_OPENSSL
		toWriteSize = 0;
		if ( !EVP_DecryptUpdate( &ctx, outBuff, ( int* )&toWriteSize,
			inpBuff, readedCount ) )
		{
			return false;
		}
		#else
		AES_DecryptUpdate( &ctx, inpBuff, readedCount, outBuff, &toWriteSize );
		#endif
		*time += ( clock() - prevTime ) / CLOCKS_PER_SEC;
		
		if ( toWriteSize > 0 )
		{
			fwrite( outBuff, toWriteSize, 1, outFile );
		}
	}
	
	#ifdef USE_OPENSSL
	toWriteSize = 0;
	if ( !EVP_DecryptFinal_ex( &ctx, outBuff, ( int* )&toWriteSize ) )
	{
		return false;
	}
	EVP_CIPHER_CTX_cleanup( &ctx );
	#else
	AES_DecryptFinal( &ctx, outBuff, &toWriteSize );
	#endif
	
	if ( toWriteSize > 0 )
	{
		fwrite( outBuff, toWriteSize, 1, outFile );
	}
	
	return true;
}

void CloseFiles( FILE *file1, FILE *file2 )
{
	if ( file1 != NULL ) {
		fclose( file1 );
	}
	
	if ( file2 != NULL ) {
		fclose( file2 );
	}
}
