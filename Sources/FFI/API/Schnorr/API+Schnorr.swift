//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension Bridge {
    public enum Scnhorr {}
}

extension Bridge.Scnhorr {
    public final class Wrapped: @unchecked Sendable, Hashable {
        public static let byteCount = 2 * Curve.Field.byteCount
        internal let bytes: [UInt8]
        
        public static func == (lhs: Wrapped, rhs: Wrapped) -> Bool {
            lhs.bytes == rhs.bytes
        }
        
        public func hash(into hasher: inout Hasher) {
            hasher.combine(bytes)
        }
        
        public var rawRepresentation: Data {
            Data(bytes)
        }
        
        
        public init(bytes: [UInt8]) throws {
            guard bytes.count == Self.byteCount else {
                throw Bridge.Error.failedToInitSchnorrSignatureInvalidByteCount(got: bytes.count, expected: Self.byteCount)
            }
            self.bytes = bytes
        }
    }
}


// MARK: Schnorr Sign
extension Bridge.Scnhorr {
    public static func sign(
        hashedMessage message: [UInt8],
        privateKey: Bridge.PrivateKey.Wrapped,
        input: SchnorrInput?
    ) throws -> Bridge.Scnhorr.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var signatureOut = [UInt8](repeating: 0, count: Bridge.Scnhorr.Wrapped.byteCount)
        
        var keyPair = secp256k1_keypair()
        
        try Bridge.call(
            ifFailThrow: .failedToInitializeKeyPairForSchnorrSigning
        ) { context in
            secp256k1_keypair_create(context, &keyPair, privateKey.secureBytes.backing.bytes)
        }
        
        var auxilaryRandomBytes: [UInt8]? = nil
        if let auxilaryRandomData = input?.auxilaryRandomData {
            guard auxilaryRandomData.count == Curve.Field.byteCount else {
                throw Bridge.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
            }
            auxilaryRandomBytes = [UInt8](auxilaryRandomData)
        }
        
        try Bridge.call(
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
        
        return try Bridge.Scnhorr.Wrapped(bytes: signatureOut)
    }
    
}


public struct SchnorrInput {
    public let auxilaryRandomData: Data
    public init(auxilaryRandomData: Data) {
        self.auxilaryRandomData = auxilaryRandomData
    }
}


