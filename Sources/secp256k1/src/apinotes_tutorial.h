#ifndef apinotes_tutorial_h
#define apinotes_tutorial_h

#include "../libsecp256k1/include/secp256k1_ecdh.h"
/**
 The ASN1 X9.63 ECDH variant which returns only the X component of ECDH secret (unhashed).

 *  Returns: 1 if the point was successfully hashed.
 *           0 will cause secp256k1_ecdh to fail and return 0.
 *           Other return values are not allowed, and the behaviour of
 *           secp256k1_ecdh is undefined for other return values.
 *  Out:     output:     pointer to an array to be filled by the function
 *  In:      x32:        pointer to a 32-byte x coordinate
 */
int ecdh_hash_function_asn1_x963_apinotes_test(
	unsigned char *output,
	const unsigned char *x32
);

void fill_with_fives(
	unsigned char *buf,
	int len
);

void clone_buf_of_len_three(
	unsigned char *destination,
	const unsigned char *source
);


#endif /* apinotes_tutorial_h */
