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
        for digest: D
    ) throws -> Bool {
        try Bridge.toC { bridge in
            
            var signatureBridgedToC = secp256k1_ecdsa_signature()
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
            
            withUnsafeMutableBytes(of: &signatureBridgedToC.data) { pointer in
                pointer.copyBytes(
                    from: signature.rawRepresentation.prefix(pointer.count)
                )
            }
            
            try bridge.call(ifFailThrow: .failedToUpdateContextRandomization) { context in
                secp256k1_ecdsa_verify(
                    context,
                    &signatureBridgedToC,
                    Array(digest),
                    &publicKeyBridgedToC
                )
            }
            
            return true // valid signature
        }
    }

    func isValidSignature<D: DataProtocol>(
        _ signature: ECDSASignature,
        for data: D
    ) throws -> Bool {
        try isValidSignature(signature, for: SHA256.hash(data: data))
    }
 }
