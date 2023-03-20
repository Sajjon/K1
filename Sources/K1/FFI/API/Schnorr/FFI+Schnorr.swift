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
        schnorrSignature: FFI.Schnorr.Wrapped,
        publicKey: FFI.PublicKey.Wrapped,
        message: [UInt8]
    ) throws -> Bool {
        
        try FFI.toC { ffi -> Bool in
            var publicKeyX = secp256k1_xonly_pubkey()
            
            try FFI.call(ifFailThrow: .failedToSchnorrVerifyGettingXFromPubKey) { context in
                secp256k1_xonly_pubkey_from_pubkey(
                    context,
                    &publicKeyX,
                    nil,
                    &publicKey.raw
                )
            }
            
            return ffi.validate { context in
                secp256k1_schnorrsig_verify(
                    context,
                    schnorrSignature.bytes,
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
        input: SchnorrInput?
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
        
        var auxilaryRandomBytes: [UInt8]? = nil
        if let auxilaryRandomData = input?.auxilaryRandomData {
            guard auxilaryRandomData.count == Curve.Field.byteCount else {
                throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
            }
            auxilaryRandomBytes = [UInt8](auxilaryRandomData)
        }
        
        try FFI.call(
            ifFailThrow: .failedToSchnorrSignDigest
        ) { context in
            secp256k1_schnorrsig_sign32(
                context,
                &signatureOut,
                message,
                &keyPair,
                auxilaryRandomBytes
            )
        }
        
        return try FFI.Schnorr.Wrapped(bytes: signatureOut)
    }

}

// MARK: SchnorrInput
public struct SchnorrInput {
    public let auxilaryRandomData: Data
    public init(auxilaryRandomData: Data) {
        self.auxilaryRandomData = auxilaryRandomData
    }
}


