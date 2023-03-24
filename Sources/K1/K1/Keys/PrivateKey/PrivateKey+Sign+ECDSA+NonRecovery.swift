//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

// MARK: ECDSA Non-Recoverable
extension K1.PrivateKey {
    
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
    public func ecdsaSignNonRecoverable(
        hashed: some DataProtocol,
        input: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.NonRecoverable.Signature {
        try K1.ECDSA.NonRecoverable.Signature(
            wrapped: FFI.ECDSA.NonRecovery.sign(
                hashedMessage: [UInt8](hashed),
                privateKey: wrapped,
                input: input
            )
        )
    }
    
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of the digest you provide over the `secp256k1` elliptic curve.
    public func ecdsaSignNonRecoverable(
        digest: some Digest,
        input: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.NonRecoverable.Signature {
        try ecdsaSignNonRecoverable(
            hashed: Data(digest),
            input: input
        )
    }
    
    /// Generates an elliptic curve digital signature algorithm (ECDSA) signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
    public func ecdsaSignNonRecoverable(
        unhashed: some DataProtocol,
        input: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.NonRecoverable.Signature {
        try ecdsaSignNonRecoverable(
            digest: SHA256.hash(data: unhashed),
            input: input
        )
    }
}
