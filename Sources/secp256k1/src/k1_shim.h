#ifndef k1_shim_h
#define k1_shim_h

typedef enum secp256k1_result {
  SECP256K1_RESULT_SUCCESS = 1,
  SECP256K1_RESULT_FAILURE = 0,
} secp256k1_result;

typedef enum secp256k1_pubkey_cmp_result {
  SECP256K1_PUBKEY_CMP_EQUAL = 0,
  SECP256K1_PUBKEY_CMP_LHS_IS_GREATER = 1,
  SECP256K1_PUBKEY_CMP_RHS_IS_GREATER = -1,
} secp256k1_pubkey_cmp_result;

typedef enum secp256k1_normalize_sig_result {
  SECP256K1_NORMALIZE_SIG_ALREADY_NORMALIZED = 0,
  SECP256K1_NORMALIZE_SIG_WASNT_NORMALIZED = 1,
} secp256k1_normalize_sig_result;


typedef enum secp256k1_verify_sig_result {
  SECP256K1_VERIFY_SIG_UNPARSABLE_OR_INCORRECT = 0,
  SECP256K1_VERIFY_SIG_CORRECT = 1,
} secp256k1_verify_sig_result;

#include "../libsecp256k1/include/secp256k1.h"

static inline secp256k1_pubkey_cmp_result
secp256k1_ec_pubkey_cmp_result(
  const secp256k1_context *ctx,
  const secp256k1_pubkey *lhs,
  const secp256k1_pubkey *rhs
) {
  int r = secp256k1_ec_pubkey_cmp(ctx, lhs, rhs);
  return r < 0 ? SECP256K1_PUBKEY_CMP_RHS_IS_GREATER
       : r > 0 ? SECP256K1_PUBKEY_CMP_LHS_IS_GREATER
               : SECP256K1_PUBKEY_CMP_EQUAL;
}

#endif /* k1_shim_h */
