//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension FFI {
    enum Schnorr {}
}

// MARK: Schnorr Validate
extension FFI.Schnorr {
    static func isValid(
        signature: FFI.Schnorr.Wrapped,
        publicKey: FFI.PublicKey.Wrapped,
        message: [UInt8]
    ) throws -> Bool {
        
        try FFI.toC { ffi -> Bool in
            var publicKeyX = secp256k1_xonly_pubkey()
            var publicKeyRaw = publicKey.raw
            try FFI.call(ifFailThrow: .failedToSchnorrVerifyGettingXFromPubKey) { context in
                secp256k1_xonly_pubkey_from_pubkey(
                    context,
                    &publicKeyX,
                    nil,
                    &publicKeyRaw
                )
            }
            
            return ffi.validate { context in
                secp256k1_schnorrsig_verify(
                    context,
                    signature.bytes,
                    message,
                    message.count,
                    &publicKeyX
                )
            }
        }
    }
}

// MARK: Schnorr Sign
extension FFI.Schnorr {
    static func sign(
        hashedMessage message: [UInt8],
        privateKey: FFI.PrivateKey.Wrapped,
        input: K1.Schnorr.SigningOptions = .default
    ) throws -> FFI.Schnorr.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var signatureOut = [UInt8](repeating: 0, count: FFI.Schnorr.Wrapped.byteCount)
        
        var keyPair = secp256k1_keypair()
        
        try FFI.call(
            ifFailThrow: .failedToInitializeKeyPairForSchnorrSigning
        ) { context in
            secp256k1_keypair_create(context, &keyPair, privateKey.secureBytes.backing.bytes)
        }
        
        
        try FFI.call(
            ifFailThrow: .failedToSchnorrSignDigest
        ) { context in
            secp256k1_schnorrsig_sign32(
                context,
                &signatureOut,
                message,
                &keyPair,
                input.auxilaryRandomData?.aux
            )
        }
        
        return try FFI.Schnorr.Wrapped(bytes: signatureOut)
    }

}
