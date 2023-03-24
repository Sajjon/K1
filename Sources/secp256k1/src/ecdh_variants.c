//
//  ecdh_variants.c
//  
//
//  Created by Alexander Cyon on 2022-01-31.
//

#include "./ecdh_variants.h"
#include <string.h>

int ecdh_unsafe_whole_point(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)data;
    /* Save x and y as uncompressed public key */
    output[0] = 0x04;
    memcpy(output + 1, x32, 32);
    memcpy(output + 33, y32, 32);
    return 1;
}

int ecdh_asn1_x963(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}
