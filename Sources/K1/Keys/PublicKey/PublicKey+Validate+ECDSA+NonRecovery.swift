//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest

// MARK: Validate ECDSA Non-Recoverable
extension K1.PublicKey {
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on some _hash_ over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The (non-recoverable) signature to check against the _hashed_ data.
    ///   - hashed: The _hashed_ data covered by the signature.
    ///   - mode: Whether or not to consider malleable signatures valid.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given _hashed_ data.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureNonRecoverable,
        hashed: some DataProtocol,
        input: K1.ECDSA.ValidationInput = .default
    ) -> Bool {
        do {
            return try FFI.ECDSA.NonRecovery.isValid(
                ecdsaSignature: signature.wrapped,
                publicKey: self.wrapped,
                message: [UInt8](hashed),
                input: input
            )
        } catch {
            return false
        }
    }
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a digest over the `secp256k1` elliptic curve.
    /// - Parameters:
    ///   - signature: The (non-recoverable) signature to check against the given digest.
    ///   - digest: The digest covered by the signature.
    ///   - mode: Whether or not to consider malleable signatures valid.
    /// - Returns: A Boolean value that’s true if the signature is valid for the given digest.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureNonRecoverable,
        digest: some Digest,
        input: K1.ECDSA.ValidationInput = .default
    ) -> Bool {
        isValidECDSASignature(
            signature,
            hashed: Data(digest),
            input: input
        )
    }

}
