#ifndef _AES_IMPL_H_
#define _AES_IMPL_H_

#include "aes.h"

void SubBytes( AesState state );
void InvSubBytes( AesState state );
void ShiftRows( AesState state );
void InvShiftRows( AesState state );
void MixColumns( AesState state );
void InvMixColumns( AesState state );

#endif // _AES_IMPL_H_
