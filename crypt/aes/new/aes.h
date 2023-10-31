#ifndef _AES_H_
#define _AES_H_

#include <stdbool.h>
#include "utils.h"

#define BLOCK_SIZE 16
#define IV_SIZE BLOCK_SIZE 
#define MAX_KEY_SIZE 32
#define MAX_ROUNDS 14
#define STATE_SIZE 4

#define ENC_UPDATE_PROTO struct _AES_CTX *ctx, \
	byte_t *plain, size_t blocksCount, \
	byte_t *cipher

#define DEC_UPDATE_PROTO struct _AES_CTX *ctx, \
	byte_t *cipher, size_t blocksCount, \
	byte_t *plain

#define ENC_BLOCK_PROTO AesState state, \
	KeysShedule roundKeys 

#define DEC_BLOCK_PROTO AesState state, \
	KeysShedule roundKeys, \
	int roundsCount

typedef enum {
	e_CBC = 0,
	e_CFB,
	e_ECB,
	e_OFB,
	e_InvalidMode	
} CryptMode;

typedef enum {
	e_EncryptOp,
	e_DecryptOp
} OperationType;

typedef byte_t AesState[ STATE_SIZE ][ STATE_SIZE ];
typedef byte_t KeysShedule[ STATE_SIZE * ( MAX_ROUNDS + 1 ) ][ STATE_SIZE ];

typedef struct _AES_CTX {
	AesState state;
	
	byte_t key[ MAX_KEY_SIZE ];	
	byte_t iv[ IV_SIZE ];
	
	int keySize;
	CryptMode mode;
	int roundsCount;
	OperationType operation;
	
	// encryption fields
	void ( *encUpdFun )( ENC_UPDATE_PROTO );
	void ( *encBlockFun )( ENC_BLOCK_PROTO );
	
	// decryption fields
	void ( *decUpdFun )( DEC_UPDATE_PROTO );
	void ( *decBlockFun )( DEC_BLOCK_PROTO );
	byte_t prevBlock[ BLOCK_SIZE ];
	
	byte_t remain[ BLOCK_SIZE ];
	int remainSize;
	size_t blocksCount;
	
	KeysShedule roundKeys;
} AES_CTX;

typedef void ( *EncryptUpdateFun )( ENC_UPDATE_PROTO );
typedef void ( *DecryptUpdateFun )( DEC_UPDATE_PROTO );

typedef void ( *EncryptBlockFun )( ENC_BLOCK_PROTO );
typedef void ( *DecryptBlockFun )( DEC_BLOCK_PROTO );


// encryption
bool AES_EncryptInit( AES_CTX *ctx, int keySize, byte_t *key, byte_t *iv,
	CryptMode mode );

void AES_EncryptUpdate( struct _AES_CTX *ctx,
	byte_t *plain, size_t plainSize,
	byte_t *cipher, size_t *cipherSize
);

void AES_EncryptFinal( AES_CTX *ctx, byte_t *cipher, size_t *finalSize );

// decryption
bool AES_DecryptInit( AES_CTX *ctx, int keySize, byte_t *key, byte_t *iv,
	CryptMode mode );

void AES_DecryptUpdate( AES_CTX *ctx,
	byte_t *cipher, size_t cipherSize,
	byte_t *plain, size_t *plainSize );

void AES_DecryptFinal( AES_CTX *ctx, byte_t *plain, size_t *finalSize );

#endif // _AES_H_
