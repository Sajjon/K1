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
        _ signature: K1.ECDSA.Recoverable.Signature,
        hashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                hashed: hashed,
                options: options
            )
        } catch {
            return false
        }
    }
    
    /// Converts a recoverable ECDSA signature to
    /// non-recoverable and validates it against
    /// a `SHA256` hashed messages for this public key.
    public func isValidECDSASignature(
        _ signature: K1.ECDSA.Recoverable.Signature,
        digest: some Digest,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                digest: digest,
                options: options
            )
        } catch {
            return false
        }
    }

    /// `SHA256` hashed messages and converts a
    /// recoverable ECDSA signature to non-recoverable and
    /// validates it against the hashed message for this public key.
    public func isValidECDSASignature(
        _ signature: K1.ECDSA.Recoverable.Signature,
        unhashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                unhashed: unhashed,
                options: options
            )
        } catch {
            return false
        }
    }
    
}
