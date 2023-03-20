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

    public init(compact: Compact) throws {
        try self.init(
            wrapped: FFI.ECDSA.Recovery.deserializeCompact(
                rs: [UInt8](compact.rs),
                recoveryID: compact.recoveryID.recid
            )
        )
    }
    
    public init(rs: Data, recoveryID: RecoveryID) throws {
        try self.init(compact: .init(rs: rs, recoveryID: recoveryID))
    }
    

    public init(
        rawRepresentation: some DataProtocol,
        format: Compact.SerializationFormat = .default
    ) throws {
        
        let expected = ECDSASignatureRecoverable.Compact.byteCount
        guard
            rawRepresentation.count == expected
        else {
            throw K1.Error.incorrectByteCountOfRawRecoverableSignature(
                got: rawRepresentation.count,
                expected: expected
            )
        }
        
        let data: Data = {
            switch format {
            case .rsv: return Data(rawRepresentation)
            case .vrs:
                let vData = Data([rawRepresentation.first!]) // safe since we asserted length above
                let rsData = Data(rawRepresentation.suffix(ECDSASignatureRecoverable.Compact.byteCountRS)) // safe since we asserted length above
                // Reverse vrs => rsv
                return rsData + vData
            }
        }()
        try self.init(
            wrapped: FFI.ECDSA.Recovery.from(rawRepresentation: data)
        )
    }
    
  
}

// MARK: Serialize
extension ECDSASignatureRecoverable {
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func compact() throws -> Compact {
        
        let (rs, recid) = try FFI.ECDSA.Recovery.serializeCompact(
            wrapped
        )
        
        return try .init(
            rs: Data(rs),
            recoveryID: .init(recid: recid)
        )
    }
    
    public struct Compact: Sendable, Hashable {
        public static let byteCount = Self.byteCountRS + 1
        public static let byteCountRS = 2 * Curve.Field.byteCount
        public let rs: Data
        public let recoveryID: RecoveryID
        public init(rs: Data, recoveryID: RecoveryID) throws {
            guard rs.count == Self.byteCountRS else {
                throw K1.Error.failedToDeserializeCompactRSRecoverableSignatureInvalidByteCount(got: rs.count, expected: Self.byteCountRS)
            }
            self.rs = rs
            self.recoveryID = recoveryID
        }
        
    }
}

extension ECDSASignatureRecoverable.Compact {
    
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
                rs: Data(rawRepresentation.suffix(Self.byteCountRS)),
                recoveryID: .init(byte: rawRepresentation.first!) // force unwrap OK since we have checked length above.
            )
        case .rsv:
            try self.init(
                rs: Data(rawRepresentation.prefix(Self.byteCountRS)),
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
