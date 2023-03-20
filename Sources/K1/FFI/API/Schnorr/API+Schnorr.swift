//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension FFI {
    enum Scnhorr {}
}

extension FFI.Scnhorr {
    final class Wrapped: @unchecked Sendable, Hashable {
        static let byteCount = 2 * Curve.Field.byteCount
        internal let bytes: [UInt8]
        
        static func == (lhs: Wrapped, rhs: Wrapped) -> Bool {
            lhs.bytes == rhs.bytes
        }
        
        func hash(into hasher: inout Hasher) {
            hasher.combine(bytes)
        }
        
        var rawRepresentation: Data {
            Data(bytes)
        }
        
        
        init(bytes: [UInt8]) throws {
            guard bytes.count == Self.byteCount else {
                throw K1.Error.failedToInitSchnorrSignatureInvalidByteCount(got: bytes.count, expected: Self.byteCount)
            }
            self.bytes = bytes
        }
    }
}


// MARK: Schnorr Sign
extension FFI.Scnhorr {
    static func sign(
        hashedMessage message: [UInt8],
        privateKey: FFI.PrivateKey.Wrapped,
        input: SchnorrInput?
    ) throws -> FFI.Scnhorr.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var signatureOut = [UInt8](repeating: 0, count: FFI.Scnhorr.Wrapped.byteCount)
        
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
        
        return try FFI.Scnhorr.Wrapped(bytes: signatureOut)
    }
    
}


public struct SchnorrInput {
    public let auxilaryRandomData: Data
    public init(auxilaryRandomData: Data) {
        self.auxilaryRandomData = auxilaryRandomData
    }
}

