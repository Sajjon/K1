//
//  ecdh_variants.h
//  
//
//  Created by Alexander Cyon on 2022-01-31.
//

#ifndef ecdh_variants_h
#define ecdh_variants_h

#include "../libsecp256k1/include/secp256k1_ecdh.h"

/** An unsafe ECDH variant which returns the whole ECDH secret (uncompressed point, unhashed)
 *
 *  Returns: 1 if the point was successfully hashed.
 *           0 will cause secp256k1_ecdh to fail and return 0.
 *           Other return values are not allowed, and the behaviour of
 *           secp256k1_ecdh is undefined for other return values.
 *  Out:     output:     pointer to an array to be filled by the function
 *  In:      x32:        pointer to a 32-byte x coordinate
 *           y32:        pointer to a 32-byte y coordinate
 *           data:       arbitrary data pointer that is passed through
 */
int ecdh_hash_function_unsafe_whole_point(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data);

/** The ASN1 X9.63 ECDH variant which returns only the X component of ECDH secret (unhashed).
 *
 *  Returns: 1 if the point was successfully hashed.
 *           0 will cause secp256k1_ecdh to fail and return 0.
 *           Other return values are not allowed, and the behaviour of
 *           secp256k1_ecdh is undefined for other return values.
 *  Out:     output:     pointer to an array to be filled by the function
 *  In:      x32:        pointer to a 32-byte x coordinate
 *           y32:        pointer to a 32-byte y coordinate
 *           data:       arbitrary data pointer that is passed through
 */
int ecdh_hash_function_asn1_x963(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data);

int _ecdh_hash_function_asn1_x963_impl(
	unsigned char *output,
	const unsigned char *x32
);

#endif /* ecdh_variants_h */
