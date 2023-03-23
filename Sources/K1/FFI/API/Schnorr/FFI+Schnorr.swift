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

extension K1 {
    public enum Schnorr {}
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
        input: K1.Schnorr.Input = .default
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

// MARK: SchnorrInput
extension K1.Schnorr {
    public struct Input: Sendable, Hashable {
        
        public static let `default` = Self()
        public let auxilaryRandomData: AuxilaryRandomData?
        public init(auxilaryRandomData: AuxilaryRandomData? = nil) {
            self.auxilaryRandomData = auxilaryRandomData
        }
        public struct AuxilaryRandomData: Sendable, Hashable {
            public let aux: [UInt8]
            public init(aux: some DataProtocol) throws {
                guard aux.count == Curve.Field.byteCount else {
                    throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
                }
                self.aux = [UInt8](aux)
            }
        }
    }
}
