//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import FFI
import CryptoKit

public extension K1 {
    
    struct PublicKey: Sendable, Hashable {
        
        typealias Wrapped = Bridge.PublicKey.Wrapped
        internal let wrapped: Wrapped
        
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}

// MARK: Init
extension K1.PublicKey {
    
    public init(x963Representation: some ContiguousBytes) throws  {
        try self.init(wrapped: Bridge.PublicKey.from(x963Representation: x963Representation))
    }
}

// MARK: Serialize
extension K1.PublicKey {
    public func rawRepresentation(format: Bridge.Format) throws -> Data {
        try wrapped.rawRepresentation(format: format)
    }
    
}

// MARK: Validate ECDSA Non-Recoverable
extension K1.PublicKey {
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on some _hash_ over the `secp256k1` elliptic curve.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureNonRecoverable,
        hashed: some DataProtocol,
        mode: SignatureValidationMode = .default
    ) -> Bool {
        do {
            return try wrapped.isValid(
                ecdsaSignature: signature.wrapped,
                message: [UInt8](hashed),
                mode: mode
            )
        } catch {
            return false
        }
    }
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a digest over the `secp256k1` elliptic curve.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureNonRecoverable,
        digest: some Digest,
        mode: SignatureValidationMode = .default
    ) -> Bool {
        isValidECDSASignature(
            signature,
            hashed: Data(digest),
            mode: mode
        )
    }

}

// MARK: Validate ECDSA Recoverable
extension K1.PublicKey {
    
    /// Converts a recoverable ECDSA signature to
    /// non-recoverable and validates it against
    /// a `SHA256` hashed messages for this public key.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureRecoverable,
        hashed: some DataProtocol,
        mode: SignatureValidationMode = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                hashed: hashed,
                mode: mode
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
        mode: SignatureValidationMode = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(signature.nonRecoverable(), digest: digest, mode: mode)
        } catch {
            return false
        }
    }

}

// MARK: Validate Schnorr Signatures
extension K1.PublicKey {
    
    
    public func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        hashed: some DataProtocol
    ) -> Bool {
        do {
            return try wrapped.isValid(
                schnorrSignature: signature.wrapped,
                message: [UInt8](hashed)
            )
        } catch {
            return false
        }
    }
    
    public func isValidSchnorrSignature<D: Digest>(
        _ signature: SchnorrSignature,
        digest: D
    ) -> Bool {
        isValidSchnorrSignature(signature, hashed: Data(digest))
    }
    
    public func isValidSchnorrSignature<M: DataProtocol>(
        _ signature: SchnorrSignature,
        unhashed: M
    ) -> Bool {
        isValidSchnorrSignature(signature, digest: SHA256.hash(data: unhashed))
    }
}

// MARK: Equatable
extension K1.PublicKey {
    public static func == (lhsSelf: Self, rhsSelf: Self) -> Bool {
        let lhs = lhsSelf.wrapped
        let rhs = rhsSelf.wrapped
        do {
            return try lhs.compare(to: rhs)
        } catch {
            return lhs.withUnsafeBytes { lhsBytes in
                rhs.withUnsafeBytes { rhsBytes in
                    safeCompare(lhsBytes, rhsBytes)
                }
            }
        }
    }
}

// MARK: Hashable
extension K1.PublicKey {
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}