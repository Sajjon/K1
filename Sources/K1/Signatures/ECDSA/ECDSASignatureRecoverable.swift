//
//  File.swift
//
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

public struct ECDSASignatureRecoverable: Sendable, Hashable {
    typealias Wrapped = FFI.ECDSA.Recovery.Wrapped
    private let wrapped: Wrapped
    
    internal init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
}

// MARK: Init
extension ECDSASignatureRecoverable {

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

// MARK: Serialize
extension ECDSASignatureRecoverable {
    
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

extension ECDSASignatureRecoverable.Compact {
    
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
extension ECDSASignatureRecoverable.RecoveryID {
    var vData: Data {
        Data(
            [UInt8(rawValue)]
        )
    }
}

// MARK: Recovery
extension ECDSASignatureRecoverable {
    public func recoverPublicKey(
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped: FFI.ECDSA.Recovery.recover(wrapped, message: [UInt8](message))
        )
    }
}


// MARK: Conversion
extension ECDSASignatureRecoverable {
    public func nonRecoverable() throws -> ECDSASignatureNonRecoverable {
        try ECDSASignatureNonRecoverable(
            wrapped: FFI.ECDSA.Recovery.nonRecoverable(self.wrapped)
        )
    }
}

// MARK: Equatable
extension ECDSASignatureRecoverable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
}

// MARK: Hashable
extension ECDSASignatureRecoverable {

    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}
