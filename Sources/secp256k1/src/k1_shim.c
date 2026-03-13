#include "./k1_shim.h"
#include "../libsecp256k1/include/secp256k1.h"
#include <string.h>

//secp256k1_pubkey_cmp_result
//secp256k1_ec_pubkey_cmp_result(
//  const secp256k1_context *ctx,
//  const secp256k1_pubkey *lhs,
//  const secp256k1_pubkey *rhs
//) {
//  int r = secp256k1_ec_pubkey_cmp(ctx, lhs, rhs);
//  return r < 0 ? SECP256K1_PUBKEY_CMP_RHS_IS_GREATER
//	   : r > 0 ? SECP256K1_PUBKEY_CMP_LHS_IS_GREATER
//			   : SECP256K1_PUBKEY_CMP_EQUAL;
//}
