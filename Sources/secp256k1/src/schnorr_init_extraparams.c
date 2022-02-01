//
//  schnorr_init_extraparams.c
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

#include "schnorr_init_extraparams.h"

int schnorrsig_extra_param_init(
                                 secp256k1_schnorrsig_extraparams* params,
                                void* magic_bytes, size_t magic_len,
                                secp256k1_nonce_function_hardened noncefp,
                                void* arbdata_bytes, size_t arbdata_len
                                ) {
//    params = &SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    return 0;
}
