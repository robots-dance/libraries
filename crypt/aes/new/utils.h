#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BYTE_BITS 8
#define SHORT_BITS 16

typedef unsigned char byte_t;

uint16_t poly_div( uint16_t dividend, uint16_t divisor );
uint16_t poly_mul( uint16_t mult1, uint16_t mult2 );

byte_t gadd( byte_t b1, byte_t b2 );
byte_t gsub( byte_t b1, byte_t b2 );
byte_t gmul( byte_t b1, byte_t b2, uint16_t module, int degree );
byte_t gmod( uint16_t dividend, uint16_t divisor, int divisorDegree );

void self_memcpy( byte_t *dst, const byte_t *src, size_t size );

#endif // _UTILS_H_
