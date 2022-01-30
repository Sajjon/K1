//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//

import Foundation

// Bridge to C
import secp256k1

// MARK: - Validate (Verify)
// MARK: -
public extension K1.PublicKey {
    
    func isValidSignature<D: Digest>(
        _ signature: ECDSASignature,
        for digest: D,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try Bridge.toC { bridge in
            
            var publicKeyBridgedToC = secp256k1_pubkey()

            try bridge.call(ifFailThrow: .failedToSerializePublicKeyIntoBytes) { context in
                /* "Serialize a pubkey object into a serialized byte sequence." */
                secp256k1_ec_pubkey_parse(
                    context,
                    &publicKeyBridgedToC,
                    rawRepresentation,
                    rawRepresentation.count
                )
            }
            
            var signatureBridgedToCPotentiallyMalleable = secp256k1_ecdsa_signature()
            withUnsafeMutableBytes(of: &signatureBridgedToCPotentiallyMalleable.data) { pointer in
                pointer.copyBytes(
                    from: signature.rawRepresentation.prefix(pointer.count)
                )
            }
            
            var signatureBridgedToCNonMalleable = secp256k1_ecdsa_signature()

            let codeForSignatureWasMalleable = 1
            let signatureWasMalleableResult = bridge.callWithResultCode { context in
                secp256k1_ecdsa_signature_normalize(
                   context,
                   &signatureBridgedToCNonMalleable, // out
                   &signatureBridgedToCPotentiallyMalleable // in
               )
           }
           
            let signatureWasMalleable = signatureWasMalleableResult == codeForSignatureWasMalleable
     
            let codeForValidSignature = 1
            let validationResult = bridge.callWithResultCode { context in
                secp256k1_ecdsa_verify(
                    context,
                    &signatureBridgedToCNonMalleable,
                    Array(digest),
                    &publicKeyBridgedToC
                )
            }
            
            let isSignatureValid = validationResult == codeForValidSignature
            let acceptMalleableSignatures = mode == .acceptSignatureMalleability
            
            switch (isSignatureValid, signatureWasMalleable, acceptMalleableSignatures) {
            case (true, false, _):
//                print("💡 Signature is valid.")
                return true
            case (true, true, true):
//                print("💡 Signature was valid but malleable, since you specified to accept malleability => considering signature valid.")
                return true
            case (true, true, false):
//                print("💡 Signature was valid, but not normalized which was required => considering signature invalid.")
                return false
            case (false, _, _):
//                print("💡 Signature invalid.")
                return false
            }
        }
    }

    func isValidSignature<D: DataProtocol>(
        _ signature: ECDSASignature,
        for data: D,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try isValidSignature(signature, for: SHA256.hash(data: data), mode: mode)
    }
}


/// Validation mode controls whether or not signature malleability should
/// is forbidden or allowed. Read more about it [here][more]
///
/// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
public enum SignatureValidationMode {
    case preventSignatureMalleability
    case acceptSignatureMalleability
}

public extension SignatureValidationMode {
    static let `default`: Self = .acceptSignatureMalleability
}
