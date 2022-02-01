//
//  schnorr_init_extraparams.h
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

#ifndef schnorr_init_extraparams_h
#define schnorr_init_extraparams_h

#include <stdio.h>

#include "../libsecp256k1/include/secp256k1_schnorrsig.h"

/** Data structure that contains additional arguments for schnorrsig_sign_custom.
 *
 *  A schnorrsig_extraparams structure object can be initialized correctly by
 *  setting it to SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT.
 *
 *  Members:
 *      magic: set to SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC at initialization
 *             and has no other function than making sure the object is
 *             initialized.
 *    noncefp: pointer to a nonce generation function. If NULL,
 *             secp256k1_nonce_function_bip340 is used
 *      ndata: pointer to arbitrary data used by the nonce generation function
 *             (can be NULL). If it is non-NULL and
 *             secp256k1_nonce_function_bip340 is used, then ndata must be a
 *             pointer to 32-byte auxiliary randomness as per BIP-340.
 */
int schnorrsig_extra_param_init(
                                 secp256k1_schnorrsig_extraparams* params,
                                void* magic_bytes, size_t magic_len,
                                secp256k1_nonce_function_hardened noncefp,
                                void* arbdata_bytes, size_t arbdata_len
                                ) SECP256K1_ARG_NONNULL(1);

#endif /* schnorr_init_extraparams_h */
