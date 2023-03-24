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
    public enum Recoverable: K1Feature {
        public typealias PrivateKey = PrivateKeyOf<Self>
        public typealias PublicKey = PublicKeyOf<Self>
    }
}

// MARK: Sign
extension K1.ECDSA.Recoverable.PrivateKey {
    public func signature(
        for hashedMessage: some DataProtocol,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.Recoverable.Signature {
        try K1.ECDSA.Recoverable.Signature(
            wrapped: FFI.ECDSA.Recovery.sign(
                hashedMessage: [UInt8](hashedMessage),
                privateKey: impl.wrapped,
                options: options
            )
        )
    }
    
    public func signature(
        for digest: some Digest,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.Recoverable.Signature {
        try signature(
            for: Data(digest),
            options: options
        )
    }
    
    /// SHA256 hashes `unhashed` before signing it.
    public func signature(
        forUnhashed unhashed: some DataProtocol,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> K1.ECDSA.Recoverable.Signature {
        try signature(
            for: SHA256.hash(data: unhashed),
            options: options
        )
    }

}

// MARK: Validate
extension K1.ECDSA.Recoverable.PublicKey {
    /// Converts a recoverable ECDSA signature to
    /// non-recoverable and validates it against
    /// a `SHA256` hashed messages for this public key.
    public func isValidSignature(
        _ signature: K1.ECDSA.Recoverable.Signature,
        hashed: some DataProtocol,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        do {
            let publicKeyNonRecoverable = try K1.ECDSA.NonRecoverable.PublicKey(rawRepresentation: self.rawRepresentation)
            let signatureNonRecoverable = try signature.nonRecoverable()
            
            return publicKeyNonRecoverable.isValidSignature(
                signatureNonRecoverable,
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
    public func isValidSignature(
        _ signature: K1.ECDSA.Recoverable.Signature,
        digest: some Digest,
        options: K1.ECDSA.ValidationOptions = .default
    ) -> Bool {
        isValidSignature(
            signature,
            hashed: Data(digest),
            options: options
        )
    }

    /// `SHA256` hashed messages and converts a
    /// recoverable ECDSA signature to non-recoverable and
    /// validates it against the hashed message for this public key.
    public func isValidSignature(
        _ signature: K1.ECDSA.Recoverable.Signature,
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

extension K1.ECDSA.Recoverable {
    public struct Signature: Sendable, Hashable, ContiguousBytes {
        
        typealias Wrapped = FFI.ECDSA.Recovery.Wrapped
        private let wrapped: Wrapped
        
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}


// MARK: Init
extension K1.ECDSA.Recoverable.Signature {

    /// Compact aka `IEEE P1363` aka `R||S`.
    public init(compact: Compact) throws {
        try self.init(
            wrapped: FFI.ECDSA.Recovery.deserialize(
                compact: [UInt8](compact.compact),
                recoveryID: compact.recoveryID.recid
            )
        )
    }
    
    /// Compact aka `IEEE P1363` aka `R||S`.
    public init(compact: Data, recoveryID: RecoveryID) throws {
        try self.init(compact: .init(compact: compact, recoveryID: recoveryID))
    }

    
    public init(
        rawRepresentation: some DataProtocol
    ) throws {
        try self.init(
            wrapped: FFI.ECDSA.Recovery.deserialize(rawRepresentation: rawRepresentation)
        )
    }
}

// MARK: ContiguousBytes
extension K1.ECDSA.Recoverable.Signature {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try wrapped.withUnsafeBytes(body)
    }
}

// MARK: Serialize
extension K1.ECDSA.Recoverable.Signature {
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    /// Compact aka `IEEE P1363` aka `R||S` with `RecoveryID`
    public func compact() throws -> Compact {
        let (rs, recid) = try FFI.ECDSA.Recovery.serializeCompact(
            wrapped
        )
        return try .init(
            compact: Data(rs),
            recoveryID: .init(recid: recid)
        )
    }
    
    public struct Compact: Sendable, Hashable {
      
        /// Compact aka `IEEE P1363` aka `R||S`.
        public let compact: Data
        
        public let recoveryID: RecoveryID
      
        /// Compact aka `IEEE P1363` aka `R||S`.
        public init(
            compact: Data,
            recoveryID: RecoveryID
        ) throws {
            guard compact.count == Self.byteCountRS else {
                throw K1.Error.failedToDeserializeCompactRSRecoverableSignatureInvalidByteCount(
                    got: compact.count,
                    expected: Self.byteCountRS
                )
            }
            self.compact = compact
            self.recoveryID = recoveryID
        }
        
    }
}

extension K1.ECDSA.Recoverable.Signature.Compact {
    
    public static let byteCountRS = 2 * Curve.Field.byteCount
    public static let byteCount = Self.byteCountRS + 1
    
    /// Takes either `R || S || V` data or `V || R || S` data, as per specification of `format`.
    public init(
        rawRepresentation: some DataProtocol,
        format: SerializationFormat
    ) throws {
        guard rawRepresentation.count == Self.byteCount else {
            throw K1.Error.failedToDeserializeCompactRecoverableSignatureInvalidByteCount(got: rawRepresentation.count, expected: Self.byteCount
            )
        }
        switch format {
        case .vrs:
            try self.init(
                compact: Data(rawRepresentation.suffix(Self.byteCountRS)),
                recoveryID: .init(byte: rawRepresentation.first!) // force unwrap OK since we have checked length above.
            )
        case .rsv:
            try self.init(
                compact: Data(rawRepresentation.prefix(Self.byteCountRS)),
                recoveryID: .init(byte: rawRepresentation.last!) // force unwrap OK since we have checked length above.
            )
        }
    }
    
    public enum SerializationFormat {
        
        /// `R || S || V` - the format `libsecp256k1` v0.3.0 uses as internal representation
        /// This is the default value of this library.
        case rsv
        
        /// We use `R || S || V` as default values since `libsecp256k1` v0.3.0 uses it as its internal representation.
        public static let `default`: Self = .rsv
        
        /// `V || R || S`.
        case vrs
    }
    
    private var v: Data {
        recoveryID.vData
    }
    private var rs: Data {
        compact
    }
    
    func serialize(format: SerializationFormat) -> Data {
        switch format {
        case .rsv:
            return rs + v
        case .vrs:
            return v + rs
        }
    }
}
extension K1.ECDSA.Recoverable.Signature.RecoveryID {
    var vData: Data {
        Data(
            [UInt8(rawValue)]
        )
    }
}

// MARK: Recovery
extension K1.ECDSA.Recoverable.Signature {
    public func recoverPublicKey(
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped: FFI.ECDSA.Recovery.recover(wrapped, message: [UInt8](message))
        )
    }
}


// MARK: Conversion
extension K1.ECDSA.Recoverable.Signature {
    public func nonRecoverable() throws -> K1.ECDSA.NonRecoverable.Signature {
        try K1.ECDSA.NonRecoverable.Signature(
            wrapped: FFI.ECDSA.Recovery.nonRecoverable(self.wrapped)
        )
    }
}

// MARK: Equatable
extension K1.ECDSA.Recoverable.Signature {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
}

// MARK: Hashable
extension K1.ECDSA.Recoverable.Signature {

    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}
