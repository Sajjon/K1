//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

// MARK: Validate Schnorr Signatures
extension K1.PublicKey {
    
    /// Verifies a Schnorr signature on some _hash_ over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The Schnorr signature to check against the _hashed_ data.
    ///   - hashed: The _hashed_ data covered by the signature.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given _hashed_ data.
    public func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        hashed: some DataProtocol
    ) -> Bool {
        do {
            return try FFI.Schnorr.isValid(
                schnorrSignature: signature.wrapped,
                publicKey: self.wrapped,
                message: [UInt8](hashed)
            )
        } catch {
            return false
        }
    }
    
    
    /// Verifies a Schnorr signature on a digest over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The Schnorr signature to check against the given digest.
    ///   - digest: The digest covered by the signature.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given digest.
    public func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        digest: some Digest
    ) -> Bool {
        isValidSchnorrSignature(
            signature,
            hashed: [UInt8](digest)
        )
    }
    
    /// Verifies a Schnorr signature on a block of data over the `secp256k1` elliptic curve.
    ///
    /// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSchnorrSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
    /// `isValidSchnorrSignature(_:hashed:input)`.
    /// - Parameters:
    ///   - signature: The Schnorr signature to check against the block of data.
    ///   - unhashed: The block of data covered by the signature.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given block of data.
    public func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        unhashed: some DataProtocol
    ) -> Bool {
        isValidSchnorrSignature(
            signature,
            digest: SHA256.hash(data: unhashed)
        )
    }
    
}
