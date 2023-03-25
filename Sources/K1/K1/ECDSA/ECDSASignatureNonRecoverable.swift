//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

extension K1.ECDSA {
    
    /// A mechanism used to create or verify a cryptographic signature using the `secp256k1` elliptic curve digital signature algorithm (ECDSA), signatures that do not offer recovery of the public key.
    public enum NonRecoverable: K1Feature {
        
        /// A `secp256k1` private key used to create cryptographic signatures,
        /// more specifically ECDSA signatures, that do not offer recovery of the public key.
        public typealias PrivateKey = PrivateKeyOf<Self>
        
        /// A `secp256k1` public key used to verify cryptographic signatures,
        /// more specifically ECDSA signatures, that do not offer recovery of the public key.
        public typealias PublicKey = PublicKeyOf<Self>
    }
}

extension K1.ECDSA.NonRecoverable {
    public struct Signature: Sendable, Hashable, ContiguousBytes {
        
        typealias Wrapped = FFI.ECDSA.NonRecovery.Wrapped
        internal let wrapped: Wrapped
        
        init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}

// MARK: Sign
extension K1.ECDSA.NonRecoverable.PrivateKey {
    
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - hashed: The _hashed_ data to sign.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: The signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
    public func signature(
        for hashed: some DataProtocol,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.NonRecoverable.Signature {
        try K1.ECDSA.NonRecoverable.Signature(
            wrapped: FFI.ECDSA.NonRecovery.sign(
                hashedMessage: [UInt8](hashed),
                privateKey: impl.wrapped,
                options: options
            )
        )
    }
    
    /// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of the digest you provide over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - digest: The digest of the data to sign.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: The signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
    public func signature(
        for digest: some Digest,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.NonRecoverable.Signature {
        try signature(
            for: Data(digest),
            options: options
        )
    }
    
    /// Generates an elliptic curve digital signature algorithm (ECDSA) signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
    /// - Parameters:
    ///   - unhashed: The data hash and then to sign.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: The signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
    public func signature(
        forUnhashed unhashed: some DataProtocol,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.NonRecoverable.Signature {
        try signature(
            for: SHA256.hash(data: unhashed),
            options: options
        )
    }
}


// MARK: Validate
extension K1.ECDSA.NonRecoverable.PublicKey {
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on some _hash_ over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The (non-recoverable) signature to check against the _hashed_ data.
    ///   - hashed: The _hashed_ data covered by the signature.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given _hashed_ data.
    public func isValidSignature(
        _ signature: K1.ECDSA.NonRecoverable.Signature,
        hashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        do {
            return try FFI.ECDSA.NonRecovery.isValid(
                ecdsaSignature: signature.wrapped,
                publicKey: self.impl.wrapped,
                message: [UInt8](hashed),
                options: options
            )
        } catch {
            return false
        }
    }
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a digest over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The (non-recoverable) signature to check against the given digest.
    ///   - digest: The digest covered by the signature.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given digest.
    public func isValidSignature(
        _ signature: K1.ECDSA.NonRecoverable.Signature,
        digest: some Digest,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        isValidSignature(
            signature,
            hashed: Data(digest),
            options: options
        )
    }

    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a block of data over the `secp256k1` elliptic curve.
    ///
    /// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
    /// `isValidSignature(_:hashed:input)`.
    ///
    /// - Parameters:
    ///   - signature: The (non-recoverable) signature to check against the given digest.
    ///   - unhashed: The block of data covered by the signature.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given block of data.
    public func isValidSignature(
        _ signature: K1.ECDSA.NonRecoverable.Signature,
        unhashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        isValidSignature(
            signature,
            digest: SHA256.hash(data: unhashed),
            options: options
        )
    }
}


// MARK: Inits
extension K1.ECDSA.NonRecoverable.Signature {
    
    public init(compactRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: FFI.ECDSA.NonRecovery.from(compactBytes: [UInt8](compactRepresentation))
        )
    }
    
    public init(derRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: FFI.ECDSA.NonRecovery.from(derRepresentation: [UInt8](derRepresentation))
        )
    }
}

// MARK: ContiguousBytes
extension K1.ECDSA.NonRecoverable.Signature {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try wrapped.withUnsafeBytes(body)
    }
}

// MARK: Serialize
extension K1.ECDSA.NonRecoverable.Signature {
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func compactRepresentation() throws -> Data {
        try FFI.ECDSA.NonRecovery.compact(wrapped)
    }
    
    public func derRepresentation() throws -> Data {
        try FFI.ECDSA.NonRecovery.der(wrapped)
    }
}


// MARK: Recover
extension K1.ECDSA.NonRecoverable.Signature {
    public func recoverPublicKey(
        recoveryID: K1.ECDSA.Recoverable.Signature.RecoveryID,
        message: some DataProtocol
    ) throws -> K1.ECDSA.NonRecoverable.PublicKey {
        let wrapped = try FFI.ECDSA.NonRecovery.recoverPublicKey(
            self.wrapped,
            recoveryID: recoveryID.recid,
            message: [UInt8](message)
        )
        let impl = K1._PublicKeyImplementation(wrapped: wrapped)
        return K1.ECDSA.NonRecoverable.PublicKey(impl: impl)
    }
}

extension K1.ECDSA.NonRecoverable.Signature {
    internal static let byteCount = FFI.ECDSA.Recovery.byteCount
}

// MARK: Equatable
extension K1.ECDSA.NonRecoverable.Signature {
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
}

// MARK: Hashable
extension K1.ECDSA.NonRecoverable.Signature {
    
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
    
}
