//
//  ecdh_no_hashfp.c
//  
//
//  Created by Alexander Cyon on 2022-01-31.
//

#include "./ecdh_no_hashfp.h"
#include <string.h>

int ecdh_skip_hash_extract_x_and_y(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)data;
    /* Save x and y as uncompressed public key */
    output[0] = 0x04;
    memcpy(output + 1, x32, 32);
    memcpy(output + 33, y32, 32);
    return 1;
}

int ecdh_skip_hash_extract_only_x(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}
