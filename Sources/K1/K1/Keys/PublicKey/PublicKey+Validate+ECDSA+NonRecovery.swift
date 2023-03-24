//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

// MARK: Validate ECDSA Non-Recoverable
extension K1.PublicKey {
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on some _hash_ over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The (non-recoverable) signature to check against the _hashed_ data.
    ///   - hashed: The _hashed_ data covered by the signature.
    ///   - options: Whether or not to consider malleable signatures valid.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given _hashed_ data.
    public func isValidECDSASignature(
        _ signature: K1.ECDSA.NonRecoverable.Signature,
        hashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        do {
            return try FFI.ECDSA.NonRecovery.isValid(
                ecdsaSignature: signature.wrapped,
                publicKey: self.wrapped,
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
    public func isValidECDSASignature(
        _ signature: K1.ECDSA.NonRecoverable.Signature,
        digest: some Digest,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        isValidECDSASignature(
            signature,
            hashed: Data(digest),
            options: options
        )
    }

    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a block of data over the `secp256k1` elliptic curve.
    ///
    /// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidECDSASignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
    /// `isValidECDSASignature(_:hashed:input)`.
    public func isValidECDSASignature(
        _ signature: K1.ECDSA.NonRecoverable.Signature,
        unhashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        isValidECDSASignature(
            signature,
            digest: SHA256.hash(data: unhashed),
            options: options
        )
    }
}
