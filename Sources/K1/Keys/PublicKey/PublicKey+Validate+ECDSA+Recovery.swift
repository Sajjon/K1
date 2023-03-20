//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest

// MARK: Validate ECDSA Recoverable
extension K1.PublicKey {
    
    /// Converts a recoverable ECDSA signature to
    /// non-recoverable and validates it against
    /// a `SHA256` hashed messages for this public key.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureRecoverable,
        hashed: some DataProtocol,
        input: K1.ECDSA.ValidationInput = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                hashed: hashed,
                input: input
            )
        } catch {
            return false
        }
    }
    
    /// Converts a recoverable ECDSA signature to
    /// non-recoverable and validates it against
    /// a `SHA256` hashed messages for this public key.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureRecoverable,
        digest: some Digest,
        input: K1.ECDSA.ValidationInput = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                digest: digest,
                input: input
            )
        } catch {
            return false
        }
    }

}
