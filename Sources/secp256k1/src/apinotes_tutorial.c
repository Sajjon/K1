//
//  apinotes_tutorial.c
//  K1
//
//  Created by Alexander Cyon on 2026-02-01.
//

#include "./apinotes_tutorial.h"
#include "./ecdh_variants.h"
#include <string.h>

int ecdh_hash_function_asn1_x963_apinotes_test(
	unsigned char *output,
	const unsigned char *x32
) {
	return _ecdh_hash_function_asn1_x963_impl(
		output,
		x32
	);
}

void fill_with_fives(
	unsigned char *buf,
	int len
) {
	memset(buf, 5, len);
}

void clone_buf_of_len_three(
	unsigned char *destination,
	const unsigned char *source
) {
	memcpy(destination, source, 3);
}
