#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "aes.h"

#define BYTE_BITS 8
#define SBOX_SIZE 16
#define SBYTES( b ) ( SBox[ ( b ) >> 4 ][ ( b ) & 0x0F ] )
#define INVSBYTES( b ) ( InvSBox[ ( b ) >> 4 ][ ( b ) & 0x0F ] )

#define APPLY_SBYTES( state, i, j, temp ) do { \
	temp = state[ i ][ j ]; \
	state[ i ][ j ] = SBYTES( temp ); \
} while ( 0 );

#define APPLY_INVSBYTES( state, i, j, temp ) do { \
	temp = state[ i ][ j ]; \
	state[ i ][ j ] = INVSBYTES( temp ); \
} while ( 0 );

#define ADD_ROUND_KEY_TO_COL( state, colIndex, keys ) do { \
	state[ 0 ][ colIndex ] ^= keys[ 0 ]; \
	state[ 1 ][ colIndex ] ^= keys[ 1 ]; \
	state[ 2 ][ colIndex ] ^= keys[ 2 ]; \
	state[ 3 ][ colIndex ] ^= keys[ 3 ]; \
} while ( 0 );

#define ENCRYPT_ROUND( state, keys ) do { \
	SubBytes( state ); \
	ShiftRows( state ); \
	MixColumns( state ); \
	AddRoundKey( state, keys ); \
	keys += BLOCK_SIZE; \
} while ( 0 );

#define DECRYPT_ROUND( state, keys ) do { \
	InvShiftRows( state ); \
	InvSubBytes( state ); \
	AddRoundKey( state, keys ); \
	InvMixColumns( state ); \
	keys -= BLOCK_SIZE; \
} while ( 0 );

#define FINIT_ENCRYPT_BLOCK( state, keys ) do { \
	SubBytes( state ); \
	ShiftRows( state ); \
	AddRoundKey( state, keys ); \
} while ( 0 );

#define FINIT_DECRYPT_BLOCK( state, keys ) do { \
	InvShiftRows( state ); \
	InvSubBytes( state ); \
	AddRoundKey( state, keys ); \
} while ( 0 );

#define ZERO_STATE( state ) do { \
	  *( uint32_t* )( state ) = 0; \
	*( ( uint32_t* )( state ) + 1 ) = 0; \
	*( ( uint32_t* )( state ) + 2 ) = 0; \
	*( ( uint32_t* )( state ) + 3 ) = 0; \
} while ( 0 );

#define COPY_ECB_TO_STATE( state, plain ) do { \
	/* copy the first row */; \
	state[ 0 ][ 0 ] = plain[ 0 ]; \
	state[ 0 ][ 1 ] = plain[ 4 ]; \
	state[ 0 ][ 2 ] = plain[ 8 ]; \
	state[ 0 ][ 3 ] = plain[ 12 ]; \
	; \
	/* copy the second row */; \
	state[ 1 ][ 0 ] = plain[ 1 ]; \
	state[ 1 ][ 1 ] = plain[ 5 ]; \
	state[ 1 ][ 2 ] = plain[ 9 ]; \
	state[ 1 ][ 3 ] = plain[ 13 ] ; \
	; \
	/* copy the third row */; \
	state[ 2 ][ 0 ] = plain[ 2 ]; \
	state[ 2 ][ 1 ] = plain[ 6 ]; \
	state[ 2 ][ 2 ] = plain[ 10 ]; \
	state[ 2 ][ 3 ] = plain[ 14 ]; \
	; \
	/* copy the fourth row */; \
	state[ 3 ][ 0 ] = plain[ 3 ]; \
	state[ 3 ][ 1 ] = plain[ 7 ]; \
	state[ 3 ][ 2 ] = plain[ 11 ]; \
	state[ 3 ][ 3 ] = plain[ 15 ]; \
} while ( 0 );

#define COPY_CBC_TO_STATE( state, plain ) do { \
	/* copy the first row */; \
	state[ 0 ][ 0 ] ^= plain[ 0 ]; \
	state[ 0 ][ 1 ] ^= plain[ 4 ]; \
	state[ 0 ][ 2 ] ^= plain[ 8 ]; \
	state[ 0 ][ 3 ] ^= plain[ 12 ]; \
	; \
	/* copy the second row */; \
	state[ 1 ][ 0 ] ^= plain[ 1 ]; \
	state[ 1 ][ 1 ] ^= plain[ 5 ]; \
	state[ 1 ][ 2 ] ^= plain[ 9 ]; \
	state[ 1 ][ 3 ] ^= plain[ 13 ] ; \
	; \
	/* copy the third row */; \
	state[ 2 ][ 0 ] ^= plain[ 2 ]; \
	state[ 2 ][ 1 ] ^= plain[ 6 ]; \
	state[ 2 ][ 2 ] ^= plain[ 10 ]; \
	state[ 2 ][ 3 ] ^= plain[ 14 ]; \
	; \
	/* copy the fourth row */; \
	state[ 3 ][ 0 ] ^= plain[ 3 ]; \
	state[ 3 ][ 1 ] ^= plain[ 7 ]; \
	state[ 3 ][ 2 ] ^= plain[ 11 ]; \
	state[ 3 ][ 3 ] ^= plain[ 15 ]; \
} while ( 0 );

#define COPY_FROM_STATE( cipher, state ) do { \
	/* save the first row */ \
	cipher[ 0 ] = state[ 0 ][ 0 ]; \
	cipher[ 1 ] = state[ 1 ][ 0 ]; \
	cipher[ 2 ] = state[ 2 ][ 0 ]; \
	cipher[ 3 ] = state[ 3 ][ 0 ]; \
	; \
	/* save the second row */ \
	cipher[ 4 ] = state[ 0 ][ 1 ]; \
	cipher[ 5 ] = state[ 1 ][ 1 ]; \
	cipher[ 6 ] = state[ 2 ][ 1 ]; \
	cipher[ 7 ] = state[ 3 ][ 1 ]; \
	; \
	/* save the third row */ \
	cipher[ 8 ]  = state[ 0 ][ 2 ]; \
	cipher[ 9 ]  = state[ 1 ][ 2 ]; \
	cipher[ 10 ] = state[ 2 ][ 2 ]; \
	cipher[ 11 ] = state[ 3 ][ 2 ]; \
	; \
	/* save the fourth row */ \
	cipher[ 12 ] = state[ 0 ][ 3 ]; \
	cipher[ 13 ] = state[ 1 ][ 3 ]; \
	cipher[ 14 ] = state[ 2 ][ 3 ]; \
	cipher[ 15 ] = state[ 3 ][ 3 ]; \
} while ( 0 );

#define COPY_OFB_FROM_STATE( cipher, state, plain ) do { \
	/* save the first row */ \
	cipher[ 0 ] = state[ 0 ][ 0 ] ^ plain[ 0 ]; \
	cipher[ 1 ] = state[ 1 ][ 0 ] ^ plain[ 1 ]; \
	cipher[ 2 ] = state[ 2 ][ 0 ] ^ plain[ 2 ]; \
	cipher[ 3 ] = state[ 3 ][ 0 ] ^ plain[ 3 ]; \
	; \
	/* save the second row */ \
	cipher[ 4 ] = state[ 0 ][ 1 ] ^ plain[ 4 ]; \
	cipher[ 5 ] = state[ 1 ][ 1 ] ^ plain[ 5 ]; \
	cipher[ 6 ] = state[ 2 ][ 1 ] ^ plain[ 6 ]; \
	cipher[ 7 ] = state[ 3 ][ 1 ] ^ plain[ 7 ]; \
	; \
	/* save the third row */ \
	cipher[ 8 ]  = state[ 0 ][ 2 ] ^ plain[ 8 ]; \
	cipher[ 9 ]  = state[ 1 ][ 2 ] ^ plain[ 9 ]; \
	cipher[ 10 ] = state[ 2 ][ 2 ] ^ plain[ 10 ]; \
	cipher[ 11 ] = state[ 3 ][ 2 ] ^ plain[ 11 ]; \
	; \
	/* save the fourth row */ \
	cipher[ 12 ] = state[ 0 ][ 3 ] ^ plain[ 12 ]; \
	cipher[ 13 ] = state[ 1 ][ 3 ] ^ plain[ 13 ]; \
	cipher[ 14 ] = state[ 2 ][ 3 ] ^ plain[ 14 ]; \
	cipher[ 15 ] = state[ 3 ][ 3 ] ^ plain[ 15 ]; \
} while ( 0 );

#define SHIFT_BLOCK( plain, crypter ) do { \
	plain += BLOCK_SIZE; \
	crypter += BLOCK_SIZE; \
} while ( 0 );


// ==== tables ====
byte_t SBox[ SBOX_SIZE ][ SBOX_SIZE ] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

byte_t InvSBox[ SBOX_SIZE ][ SBOX_SIZE ] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
	0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
	0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
	0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
	0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
	0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
	0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
	0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
	0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
	0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
	0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
	0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
	0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
	0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
	0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
	0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
	0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

byte_t MixCol_02_product[] = {
	0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
	0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
	0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
	0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e,
	0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
	0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
	0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
	0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e,
	0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
	0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
	0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
	0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
	0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
	0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc, 0xde,
	0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
	0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe,
	0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
	0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
	0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
	0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
	0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
	0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45,
	0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
	0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
	0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
	0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85,
	0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
	0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5,
	0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
	0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
	0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
	0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5
};

byte_t MixCol_03_product[] = {
	0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09,
	0x18, 0x1b, 0x1e, 0x1d, 0x14, 0x17, 0x12, 0x11,
	0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
	0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21,
	0x60, 0x63, 0x66, 0x65, 0x6c, 0x6f, 0x6a, 0x69,
	0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
	0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59,
	0x48, 0x4b, 0x4e, 0x4d, 0x44, 0x47, 0x42, 0x41,
	0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
	0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1,
	0xf0, 0xf3, 0xf6, 0xf5, 0xfc, 0xff, 0xfa, 0xf9,
	0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
	0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9,
	0xb8, 0xbb, 0xbe, 0xbd, 0xb4, 0xb7, 0xb2, 0xb1,
	0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
	0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81,
	0x9b, 0x98, 0x9d, 0x9e, 0x97, 0x94, 0x91, 0x92,
	0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
	0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2,
	0xb3, 0xb0, 0xb5, 0xb6, 0xbf, 0xbc, 0xb9, 0xba,
	0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
	0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea,
	0xcb, 0xc8, 0xcd, 0xce, 0xc7, 0xc4, 0xc1, 0xc2,
	0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
	0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52,
	0x43, 0x40, 0x45, 0x46, 0x4f, 0x4c, 0x49, 0x4a,
	0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
	0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a,
	0x3b, 0x38, 0x3d, 0x3e, 0x37, 0x34, 0x31, 0x32,
	0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
	0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02,
	0x13, 0x10, 0x15, 0x16, 0x1f, 0x1c, 0x19, 0x1a
};

byte_t InvMixCol_09_product[] = {
	0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f,
	0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
	0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
	0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
	0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04,
	0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
	0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94,
	0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
	0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49,
	0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
	0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9,
	0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
	0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72,
	0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
	0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2,
	0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
	0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3,
	0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
	0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43,
	0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
	0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
	0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
	0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78,
	0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
	0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5,
	0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
	0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35,
	0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
	0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e,
	0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
	0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e,
	0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
};

byte_t InvMixCol_0b_product[] = {
	0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31,
	0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
	0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81,
	0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
	0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a,
	0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
	0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa,
	0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
	0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7,
	0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
	0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77,
	0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
	0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc,
	0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
	0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c,
	0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
	0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6,
	0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
	0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76,
	0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
	0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd,
	0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
	0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d,
	0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
	0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30,
	0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
	0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
	0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
	0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b,
	0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
	0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb,
	0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3
};

byte_t InvMixCol_0d_product[] = {
	0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23,
	0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
	0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3,
	0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
	0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98,
	0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
	0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48,
	0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
	0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e,
	0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
	0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e,
	0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
	0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5,
	0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
	0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25,
	0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
	0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9,
	0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
	0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29,
	0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
	0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42,
	0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
	0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92,
	0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
	0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94,
	0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
	0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
	0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
	0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f,
	0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
	0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff,
	0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
};

byte_t InvMixCol_0e_product[] = {
	0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a,
	0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
	0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca,
	0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
	0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1,
	0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
	0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11,
	0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
	0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87,
	0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
	0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67,
	0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
	0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c,
	0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
	0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc,
	0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
	0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b,
	0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
	0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b,
	0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
	0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0,
	0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
	0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50,
	0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
	0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6,
	0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
	0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
	0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
	0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d,
	0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
	0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd,
	0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
};

byte_t Signf_Rcon[] = {
	0x0, 0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};


// ==== subbytes functions ====
void SubBytes( AesState state )
{
	byte_t t;
	
	// first row
	APPLY_SBYTES( state, 0, 0, t );
	APPLY_SBYTES( state, 0, 1, t );
	APPLY_SBYTES( state, 0, 2, t );
	APPLY_SBYTES( state, 0, 3, t );
	
	// second row
	APPLY_SBYTES( state, 1, 0, t );
	APPLY_SBYTES( state, 1, 1, t );
	APPLY_SBYTES( state, 1, 2, t );
	APPLY_SBYTES( state, 1, 3, t );
	
	// third row
	APPLY_SBYTES( state, 2, 0, t );
	APPLY_SBYTES( state, 2, 1, t );
	APPLY_SBYTES( state, 2, 2, t );
	APPLY_SBYTES( state, 2, 3, t );
	
	// fourth row
	APPLY_SBYTES( state, 3, 0, t );
	APPLY_SBYTES( state, 3, 1, t );
	APPLY_SBYTES( state, 3, 2, t );
	APPLY_SBYTES( state, 3, 3, t );
}

void InvSubBytes( AesState state )
{
	byte_t t;
	
	// first row
	APPLY_INVSBYTES( state, 0, 0, t );
	APPLY_INVSBYTES( state, 0, 1, t );
	APPLY_INVSBYTES( state, 0, 2, t );
	APPLY_INVSBYTES( state, 0, 3, t );
	
	// second row
	APPLY_INVSBYTES( state, 1, 0, t );
	APPLY_INVSBYTES( state, 1, 1, t );
	APPLY_INVSBYTES( state, 1, 2, t );
	APPLY_INVSBYTES( state, 1, 3, t );
	
	// third row
	APPLY_INVSBYTES( state, 2, 0, t );
	APPLY_INVSBYTES( state, 2, 1, t );
	APPLY_INVSBYTES( state, 2, 2, t );
	APPLY_INVSBYTES( state, 2, 3, t );
	
	// fourth row
	APPLY_INVSBYTES( state, 3, 0, t );
	APPLY_INVSBYTES( state, 3, 1, t );
	APPLY_INVSBYTES( state, 3, 2, t );
	APPLY_INVSBYTES( state, 3, 3, t );
}


// ==== shift functions ====
void ShiftRows( AesState state )
{
	byte_t temp;
	
	// second row shift
	temp = state[ 1 ][ 0 ];
	state[ 1 ][ 0 ] = state[ 1 ][ 1 ];
	state[ 1 ][ 1 ] = state[ 1 ][ 2 ];
	state[ 1 ][ 2 ] = state[ 1 ][ 3 ];
	state[ 1 ][ 3 ] = temp;
	
	byte_t temp1;
	
	// third row shift
	temp = state[ 2 ][ 0 ];
	temp1 = state[ 2 ][ 1 ];
	state[ 2 ][ 0 ] = state[ 2 ][ 2 ];
	state[ 2 ][ 1 ] = state[ 2 ][ 3 ];
	state[ 2 ][ 2 ] = temp;
	state[ 2 ][ 3 ] = temp1;
	
	// fourth row shift
	temp = state[ 3 ][ 3 ];
	state[ 3 ][ 3 ] = state[ 3 ][ 2 ];
	state[ 3 ][ 2 ] = state[ 3 ][ 1 ];
	state[ 3 ][ 1 ] = state[ 3 ][ 0 ];
	state[ 3 ][ 0 ] = temp;
}

void InvShiftRows( AesState state )
{
	byte_t temp;
	
	// second row shift
	temp = state[ 1 ][ 3 ];
	state[ 1 ][ 3 ] = state[ 1 ][ 2 ];
	state[ 1 ][ 2 ] = state[ 1 ][ 1 ];
	state[ 1 ][ 1 ] = state[ 1 ][ 0 ];
	state[ 1 ][ 0 ] = temp;
	
	byte_t temp1;
	
	// third row shift
	temp = state[ 2 ][ 2 ];
	temp1 = state[ 2 ][ 3 ];
	state[ 2 ][ 2 ] = state[ 2 ][ 0 ];
	state[ 2 ][ 3 ] = state[ 2 ][ 1 ];
	state[ 2 ][ 0 ] = temp;
	state[ 2 ][ 1 ] = temp1;
	
	// fouth row shift
	temp = state[ 3 ][ 0 ];
	state[ 3 ][ 0 ] = state[ 3 ][ 1 ];
	state[ 3 ][ 1 ] = state[ 3 ][ 2 ];
	state[ 3 ][ 2 ] = state[ 3 ][ 3 ];
	state[ 3 ][ 3 ] = temp;
}

#define MIX_COL( state, colnum, s0, s1, s2, s3 ) do { \
	state[ 0 ][ colnum ] = MixCol_02_product[ s0 ] ^ \
		MixCol_03_product[ s1 ] ^ \
		s2 ^ s3; \
	state[ 1 ][ colnum ] = MixCol_02_product[ s1 ] ^ \
		MixCol_03_product[ s2 ] ^ \
		s0 ^ s3; \
	state[ 2 ][ colnum ] = MixCol_02_product[ s2 ] ^ \
		MixCol_03_product[ s3 ] ^ \
		s0 ^ s1; \
	state[ 3 ][ colnum ] = MixCol_02_product[ s3 ] ^ \
		MixCol_03_product[ s0 ] ^ \
		s1 ^ s2; \
} while ( 0 );

#define INV_MIX_COL( state, colnum, s0, s1, s2, s3 ) do { \
	state[ 0 ][ colnum ] = InvMixCol_0e_product[ s0 ] ^ \
		InvMixCol_0b_product[ s1 ] ^ \
		InvMixCol_0d_product[ s2 ] ^ \
		InvMixCol_09_product[ s3 ]; \
	state[ 1 ][ colnum ] = InvMixCol_09_product[ s0 ] ^ \
		InvMixCol_0e_product[ s1 ] ^ \
		InvMixCol_0b_product[ s2 ] ^ \
		InvMixCol_0d_product[ s3 ]; \
	state[ 2 ][ colnum ] = InvMixCol_0d_product[ s0 ] ^ \
		InvMixCol_09_product[ s1 ] ^ \
		InvMixCol_0e_product[ s2 ] ^ \
		InvMixCol_0b_product[ s3 ]; \
	state[ 3 ][ colnum ] = InvMixCol_0b_product[ s0 ] ^ \
		InvMixCol_0d_product[ s1 ] ^ \
		InvMixCol_09_product[ s2 ] ^ \
		InvMixCol_0e_product[ s3 ]; \
} while ( 0 );


// ==== mix functions ====
void MixColumns( AesState state )
{
	byte_t s0, s1, s2, s3;
	
	// first column
	s0 = state[ 0 ][ 0 ];
	s1 = state[ 1 ][ 0 ];
	s2 = state[ 2 ][ 0 ];
	s3 = state[ 3 ][ 0 ];
	MIX_COL( state, 0, s0, s1, s2, s3 );
	
	// second column
	s0 = state[ 0 ][ 1 ];
	s1 = state[ 1 ][ 1 ];
	s2 = state[ 2 ][ 1 ];
	s3 = state[ 3 ][ 1 ];
	MIX_COL( state, 1, s0, s1, s2, s3 );
	
	// third column
	s0 = state[ 0 ][ 2 ];
	s1 = state[ 1 ][ 2 ];
	s2 = state[ 2 ][ 2 ];
	s3 = state[ 3 ][ 2 ];
	MIX_COL( state, 2, s0, s1, s2, s3 );
	
	// fourth column
	s0 = state[ 0 ][ 3 ];
	s1 = state[ 1 ][ 3 ];
	s2 = state[ 2 ][ 3 ];
	s3 = state[ 3 ][ 3 ];
	MIX_COL( state, 3, s0, s1, s2, s3 );
}

void InvMixColumns( AesState state )
{
	byte_t s0, s1, s2, s3;
	
	// first column
	s0 = state[ 0 ][ 0 ];
	s1 = state[ 1 ][ 0 ];
	s2 = state[ 2 ][ 0 ];
	s3 = state[ 3 ][ 0 ];
	INV_MIX_COL( state, 0, s0, s1, s2, s3 );
	
	// second column
	s0 = state[ 0 ][ 1 ];
	s1 = state[ 1 ][ 1 ];
	s2 = state[ 2 ][ 1 ];
	s3 = state[ 3 ][ 1 ];
	INV_MIX_COL( state, 1, s0, s1, s2, s3 );
	
	// third column
	s0 = state[ 0 ][ 2 ];
	s1 = state[ 1 ][ 2 ];
	s2 = state[ 2 ][ 2 ];
	s3 = state[ 3 ][ 2 ];
	INV_MIX_COL( state, 2, s0, s1, s2, s3 );
	
	// fourth column
	s0 = state[ 0 ][ 3 ];
	s1 = state[ 1 ][ 3 ];
	s2 = state[ 2 ][ 3 ];
	s3 = state[ 3 ][ 3 ];
	INV_MIX_COL( state, 3, s0, s1, s2, s3 );
}


// ==== round keys functions ====
void SubWord( byte_t word[ STATE_SIZE ] )
{
	word[ 0 ] = SBYTES( word[ 0 ] );
	word[ 1 ] = SBYTES( word[ 1 ] );
	word[ 2 ] = SBYTES( word[ 2 ] );
	word[ 3 ] = SBYTES( word[ 3 ] );
}

void RotWord( byte_t word[ STATE_SIZE ] )
{
	byte_t zeroElem = word[ 0 ];
	word[ 0 ] = word[ 1 ];
	word[ 1 ] = word[ 2 ];
	word[ 2 ] = word[ 3 ];
	word[ 3 ] = zeroElem;
}

void XorWord( byte_t dst[ STATE_SIZE ], byte_t word[ STATE_SIZE ] )
{
	dst[ 0 ] ^= word[ 0 ];
	dst[ 1 ] ^= word[ 1 ];
	dst[ 2 ] ^= word[ 2 ];
	dst[ 3 ] ^= word[ 3 ];
}

void AddRoundKey( AesState state, byte_t *keys  )
{
	ADD_ROUND_KEY_TO_COL( state, 0, keys );
	keys += STATE_SIZE;
	
	ADD_ROUND_KEY_TO_COL( state, 1, keys );
	keys += STATE_SIZE;
	
	ADD_ROUND_KEY_TO_COL( state, 2, keys );
	keys += STATE_SIZE;
	
	ADD_ROUND_KEY_TO_COL( state, 3, keys );
}

void KeyExpansion( AES_CTX *ctx )
{
	byte_t *key = ctx->key;
	int keyWordsCount = ctx->keySize / BYTE_BITS / STATE_SIZE;
	
	int keyWordIndex = 0;
	while ( keyWordIndex < keyWordsCount )
	{
		byte_t *word = &ctx->roundKeys[ keyWordIndex ][ 0 ];
		self_memcpy( word, &key[ STATE_SIZE * keyWordIndex ], STATE_SIZE );
		keyWordIndex++;
	}
	
	byte_t Rcon[ STATE_SIZE ] = { 0, 0, 0, 0 };
	while ( keyWordIndex < STATE_SIZE * ( ctx->roundsCount + 1 ) )
	{
		byte_t word[ STATE_SIZE ];
		self_memcpy( word, &ctx->roundKeys[ keyWordIndex - 1 ][ 0 ],
			STATE_SIZE );
		if ( keyWordIndex % keyWordsCount == 0 )
		{
			RotWord( word );
			SubWord( word );
			Rcon[ 0 ] = Signf_Rcon[ keyWordIndex / keyWordsCount ];
			XorWord( word, Rcon );
		}
		else if ( keyWordsCount > 6 && keyWordIndex % keyWordsCount == 4 )
		{
			SubWord( word );
		}
		XorWord( word, &ctx->roundKeys[ keyWordIndex - keyWordsCount ][ 0 ] );
		self_memcpy( &ctx->roundKeys[ keyWordIndex ][ 0 ], word, STATE_SIZE );
		keyWordIndex++;	
	}
}


// ==== private encrypt functions ====
void AES_128_EncryptBlock( ENC_BLOCK_PROTO )
{
	byte_t *curKeys = &roundKeys[ 0 ][ 0 ];
	AddRoundKey( state, curKeys );
	curKeys += BLOCK_SIZE;
	
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	
	FINIT_ENCRYPT_BLOCK( state, curKeys );
}

void AES_192_EncryptBlock( ENC_BLOCK_PROTO )
{
	byte_t *curKeys = &roundKeys[ 0 ][ 0 ];
	AddRoundKey( state, curKeys );
	curKeys += BLOCK_SIZE;
	
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	
	FINIT_ENCRYPT_BLOCK( state, curKeys );
}

void AES_256_EncryptBlock( ENC_BLOCK_PROTO )
{
	byte_t *curKeys = &roundKeys[ 0 ][ 0 ];
	AddRoundKey( state, curKeys );
	curKeys += BLOCK_SIZE;
	
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	ENCRYPT_ROUND( state, curKeys );
	
	FINIT_ENCRYPT_BLOCK( state, curKeys );
}

void AES_ECB_EncryptUpdate( ENC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		COPY_ECB_TO_STATE( ctx->state, plain );
		ctx->encBlockFun( ctx->state, ctx->roundKeys );
		COPY_FROM_STATE( cipher, ctx->state );
		SHIFT_BLOCK( plain, cipher );
	}
}

void AES_CBC_EncryptUpdate( ENC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		COPY_CBC_TO_STATE( ctx->state, plain );
		ctx->encBlockFun( ctx->state, ctx->roundKeys );
		COPY_FROM_STATE( cipher, ctx->state );
		SHIFT_BLOCK( plain, cipher );
	}
}

void AES_CFB_EncryptUpdate( ENC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		ctx->encBlockFun( ctx->state, ctx->roundKeys );
		COPY_CBC_TO_STATE( ctx->state, plain );
		COPY_FROM_STATE( cipher, ctx->state );
		SHIFT_BLOCK( plain, cipher );
	}
}

void AES_OFB_EncryptUpdate( ENC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		ctx->encBlockFun( ctx->state, ctx->roundKeys );
		COPY_OFB_FROM_STATE( cipher, ctx->state, plain );
		SHIFT_BLOCK( plain, cipher );
	}
}


// ==== private decrypt functions ====
void AES_128_DecryptBlock( DEC_BLOCK_PROTO )
{
	byte_t *curKeys = &roundKeys[ STATE_SIZE * roundsCount ][ 0 ];
	AddRoundKey( state, curKeys );
	curKeys -= BLOCK_SIZE;
	
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	
	FINIT_DECRYPT_BLOCK( state, curKeys );
}

void AES_192_DecryptBlock( DEC_BLOCK_PROTO )
{
	byte_t *curKeys = &roundKeys[ STATE_SIZE * roundsCount ][ 0 ];
	AddRoundKey( state, curKeys );
	curKeys -= BLOCK_SIZE;
	
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	
	FINIT_DECRYPT_BLOCK( state, curKeys );
}

void AES_256_DecryptBlock( DEC_BLOCK_PROTO )
{
	byte_t *curKeys = &roundKeys[ STATE_SIZE * roundsCount ][ 0 ];
	AddRoundKey( state, curKeys );
	curKeys -= BLOCK_SIZE;
	
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	DECRYPT_ROUND( state, curKeys );
	
	FINIT_DECRYPT_BLOCK( state, curKeys );
}

void AES_ECB_DecryptUpdate( DEC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		COPY_ECB_TO_STATE( ctx->state, cipher );
		ctx->decBlockFun( ctx->state, ctx->roundKeys, ctx->roundsCount );
		COPY_FROM_STATE( plain, ctx->state );
		SHIFT_BLOCK( cipher, plain );
	}
}

void AES_CBC_DecryptUpdate( DEC_UPDATE_PROTO )
{
	byte_t *prevBlock = ctx->prevBlock;
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		COPY_ECB_TO_STATE( ctx->state, cipher );
		ctx->decBlockFun( ctx->state, ctx->roundKeys, ctx->roundsCount );
		COPY_OFB_FROM_STATE( plain, ctx->state, prevBlock );
		prevBlock = cipher; 
		SHIFT_BLOCK( cipher, plain );
	}
	self_memcpy( ctx->prevBlock, prevBlock, BLOCK_SIZE );
}

void AES_CFB_DecryptUpdate( DEC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		ctx->encBlockFun( ctx->state, ctx->roundKeys );
		COPY_OFB_FROM_STATE( plain, ctx->state, cipher );
		COPY_ECB_TO_STATE( ctx->state, cipher );
		SHIFT_BLOCK( plain, cipher );
	}
}

void AES_OFB_DecryptUpdate( DEC_UPDATE_PROTO )
{
	for ( size_t blockIndex = 0; blockIndex < blocksCount; blockIndex++ )
	{
		ctx->encBlockFun( ctx->state, ctx->roundKeys );
		COPY_OFB_FROM_STATE( plain, ctx->state, cipher );
		SHIFT_BLOCK( cipher, plain );
	}
}


// ==== public encrypt functions ====
bool AES_EncryptInit( AES_CTX *ctx, int keySize, byte_t *key, byte_t *iv,
	CryptMode mode )
{
	static const EncryptUpdateFun updateFunctions[] = {
		AES_CBC_EncryptUpdate,
		AES_CFB_EncryptUpdate,
		AES_ECB_EncryptUpdate,
		AES_OFB_EncryptUpdate
	};
	
	static const EncryptBlockFun blockFunctions[] = {
		AES_128_EncryptBlock,
		AES_192_EncryptBlock,
		AES_256_EncryptBlock
	};
	
	if ( keySize != 128 && keySize != 192 && keySize != 256 )
	{
		return false;
	}
	self_memcpy( ctx->key, key, keySize / BYTE_BITS );
	self_memcpy( ctx->iv, iv, IV_SIZE );
	
	if ( e_CBC == mode )
	{
		ZERO_STATE( ctx->state );
		COPY_CBC_TO_STATE( ctx->state, ctx->iv );
	}
	else if ( e_OFB == mode || e_CFB == mode )
	{
		COPY_ECB_TO_STATE( ctx->state, ctx->iv );
	}
	
	ctx->keySize = keySize;
	ctx->mode = mode;
	ctx->roundsCount = 10 + ( keySize / 64 - 2 ) * 2;
	ctx->operation = e_EncryptOp;
	
	ctx->encUpdFun = updateFunctions[ mode ];
	ctx->encBlockFun = blockFunctions[ keySize / 64 - 2 ];
	
	ctx->remainSize = 0;
	ctx->blocksCount = 0;
	
	KeyExpansion( ctx );
	
	return true;
}

void AES_EncryptUpdate( struct _AES_CTX *ctx,
	byte_t *plain, size_t plainSize,
	byte_t *cipher, size_t *cipherSize ) 
{
	*cipherSize = 0;
	int remainSize = ctx->remainSize;
	if ( remainSize > 0 )
	{
		bool remainNoFilled = plainSize + ( size_t )remainSize < BLOCK_SIZE;
		int toCopySize = remainNoFilled ? plainSize : BLOCK_SIZE - remainSize;
		self_memcpy( ctx->remain + remainSize, plain, toCopySize );
		plain += toCopySize;
		plainSize -= toCopySize;
		
		if ( remainNoFilled )
		{
			ctx->remainSize += toCopySize;
			return;
		}
		else {
			ctx->remainSize = 0;
		}
		
		ctx->encUpdFun( ctx, ctx->remain, 1, cipher );
		
		cipher += BLOCK_SIZE;
		*cipherSize = BLOCK_SIZE;
		ctx->blocksCount++;
	}
	else if ( plainSize < BLOCK_SIZE )
	{
		self_memcpy( ctx->remain, plain, plainSize );
		ctx->remainSize = plainSize;
		return;
	}
	
	size_t blocksCount = plainSize / BLOCK_SIZE;
	ctx->encUpdFun( ctx, plain, blocksCount, cipher );
	remainSize = plainSize % BLOCK_SIZE; 
	if ( remainSize > 0 )
	{
		self_memcpy( ctx->remain, plain + blocksCount *
			BLOCK_SIZE, remainSize );
		ctx->remainSize = remainSize;
	}
	
	*cipherSize += blocksCount * BLOCK_SIZE;
	ctx->blocksCount += blocksCount;
}

void PKCS7_PadBlock( AES_CTX *ctx )
{
	int remainSize = ctx->remainSize;
	byte_t fillVal = BLOCK_SIZE - remainSize;
	while ( remainSize < BLOCK_SIZE )
	{
		ctx->remain[ remainSize ] = fillVal;
		remainSize++;
	}
	ctx->remainSize = 0;
}

void AES_EncryptFinal( AES_CTX *ctx, byte_t *cipher, size_t *finalSize )
{
	if ( e_CFB == ctx->mode || e_OFB == ctx->mode )
	{
		int remainSize = ctx->remainSize;
		if ( remainSize > 0 )
		{
			ctx->encUpdFun( ctx, ctx->remain, 1, cipher );
			*finalSize = remainSize;
		}
		else
		{
			*finalSize = 0;
		}
	}
	else
	{
		PKCS7_PadBlock( ctx );
		ctx->encUpdFun( ctx, ctx->remain, 1, cipher );
		*finalSize = BLOCK_SIZE;
	}
}


// ==== public decrypt functions ====
bool AES_DecryptInit( AES_CTX *ctx, int keySize, byte_t *key, byte_t *iv,
	CryptMode mode )
{
	static const DecryptUpdateFun updateFunctions[] = {
		AES_CBC_DecryptUpdate,
		AES_CFB_DecryptUpdate,
		AES_ECB_DecryptUpdate,
		AES_OFB_DecryptUpdate
	};
	
	static const DecryptBlockFun decBlockFunctions[] = {
		AES_128_DecryptBlock,
		AES_192_DecryptBlock,
		AES_256_DecryptBlock
	};
	
	static const EncryptBlockFun encBlockFunctions[] = {
		AES_128_EncryptBlock,
		AES_192_EncryptBlock,
		AES_256_EncryptBlock
	};
	
	if ( keySize != 128 && keySize != 192 && keySize != 256 )
	{
		return false;
	}
	self_memcpy( ctx->key, key, keySize / BYTE_BITS );
	self_memcpy( ctx->iv, iv, IV_SIZE );
	
	if ( e_CBC == mode )
	{
		self_memcpy( ctx->prevBlock, iv, BLOCK_SIZE );
	}
	else if ( e_CFB == mode || e_OFB == mode )
	{
		COPY_ECB_TO_STATE( ctx->state, iv );
	}
	
	int keySizeIndex = keySize / 64 - 2;
	
	ctx->keySize = keySize;
	ctx->mode = mode;
	ctx->roundsCount = 10 + keySizeIndex * 2;
	ctx->operation = e_DecryptOp;
	
	ctx->decUpdFun = updateFunctions[ mode ]; 
	if ( mode != e_OFB && mode != e_CFB )
	{
		ctx->decBlockFun = decBlockFunctions[ keySizeIndex ];
	}
	else
	{
		ctx->encBlockFun = encBlockFunctions[ keySizeIndex ];
	}
	
	ctx->remainSize = 0;
	ctx->blocksCount = 0;
	
	KeyExpansion( ctx );
	
	return true;
}

void AES_DecryptUpdate( AES_CTX *ctx,
	byte_t *cipher, size_t cipherSize,
	byte_t *plain, size_t *plainSize )
{
	*plainSize = 0;
	int remainSize = ctx->remainSize;
	if ( remainSize > 0 )
	{
		bool remainNoFilled = cipherSize + ( size_t )remainSize < BLOCK_SIZE;
		int toCopySize = remainNoFilled ? cipherSize : BLOCK_SIZE - remainSize;
		self_memcpy( ctx->remain + remainSize, cipher, toCopySize );
		cipher += toCopySize;
		cipherSize -= toCopySize;
		
		if ( remainNoFilled )
		{
			ctx->remainSize += toCopySize;
			return;
		}
		else
		{
			if ( 0 == cipherSize )
			{
				return;
			}
			ctx->remainSize = 0;
		}
		
		ctx->decUpdFun( ctx, ctx->remain, 1, plain );
		
		plain += BLOCK_SIZE;
		*plainSize = BLOCK_SIZE;
		ctx->blocksCount++;
	}
	else if ( cipherSize < BLOCK_SIZE )
	{
		self_memcpy( ctx->remain, cipher, cipherSize );
		ctx->remainSize = cipherSize;
		return;
	}
	
	size_t blocksCount = cipherSize / BLOCK_SIZE;
	remainSize = cipherSize % BLOCK_SIZE; 
	if ( 0 == remainSize )
	{
		blocksCount--;
		remainSize = BLOCK_SIZE;
	}
	if ( blocksCount > 0 )
	{
		ctx->decUpdFun( ctx, cipher, blocksCount, plain );
	}
	if ( remainSize > 0 )
	{
		self_memcpy( ctx->remain, cipher + blocksCount *
			BLOCK_SIZE, remainSize );
		ctx->remainSize = remainSize;
	}
	
	*plainSize += blocksCount * BLOCK_SIZE;
	ctx->blocksCount += blocksCount;
}

byte_t PKCS7_CalcPadding( byte_t *block )
{
	int byteIndex = BLOCK_SIZE - 1;
	const byte_t lastVal = block[ byteIndex ];
	byteIndex--;
	int equalsCount = 1;
	while ( byteIndex >= 0 && lastVal == block[ byteIndex ] )
	{
		byteIndex--;
		equalsCount++;
	}
	if ( equalsCount >= lastVal )
	{
		return lastVal;
	}
	else {
		return 0;
	}
}

void AES_DecryptFinal( AES_CTX *ctx, byte_t *plain, size_t *finalSize )
{
	if ( e_CFB == ctx->mode || e_OFB == ctx->mode )
	{
		int remainSize = ctx->remainSize;
		if ( remainSize > 0 )
		{
			ctx->decUpdFun( ctx, ctx->remain, 1, plain );
			*finalSize = remainSize;
		}
		else
		{
			*finalSize = 0;
		}
	}
	else
	{
		byte_t outputBlock[ BLOCK_SIZE ];
		ctx->decUpdFun( ctx, ctx->remain, 1, outputBlock );
		byte_t paddingSize = PKCS7_CalcPadding( outputBlock );
		int toCopySize = BLOCK_SIZE - paddingSize;
		if ( toCopySize > 0 )
		{
			self_memcpy( plain, outputBlock, toCopySize );
		}
		*finalSize = toCopySize;
	}
}