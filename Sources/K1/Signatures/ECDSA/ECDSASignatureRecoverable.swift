//
//  File.swift
//
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit
import FFI
import Tagged

public struct ECDSASignatureRecoverable: Sendable, Hashable {
    typealias Wrapped = Bridge.ECDSA.Recovery.Wrapped
    private let wrapped: Wrapped
    
    internal init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
}

// MARK: Init
extension ECDSASignatureRecoverable {
    public init(compactRepresentation: Data, recoveryID: Int32) throws {
        // FIXME: Needed?
        guard
            compactRepresentation.count == ECDSASignatureNonRecoverable.byteCount
         else {
             throw Bridge.Error.incorrectByteCountOfRawSignature
         }
//        var recoverableSignature = secp256k1_ecdsa_recoverable_signature()
//        let rs = [UInt8](compactRepresentation)
//
//        try Bridge.call(ifFailThrow: .failedToParseRecoverableSignatureFromCompactRepresentation) { context in
//            secp256k1_ecdsa_recoverable_signature_parse_compact(
//                context,
//                &recoverableSignature,
//                rs,
//                recoveryID
//            )
//        }
//        self.rawRepresentation = Data(
//            bytes: &recoverableSignature.data,
//            count: MemoryLayout.size(ofValue: recoverableSignature.data)
//        )
        fatalError()
    }
    

    public init(rawRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: Bridge.ECDSA.Recovery.from(rawRepresentation: rawRepresentation)
        )
    }
    
  
}

// MARK: Serialize
extension ECDSASignatureRecoverable {
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func compact() throws -> Compact {
        
        let (rs, recid) = try Bridge.ECDSA.Recovery.serialize(
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
                throw Bridge.Error.failedToDeserializeCompactRSRecoverableSignatureInvalidByteCount(got: rs.count, expected: Self.byteCountRS)
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
            throw Bridge.Error.failedToDeserializeCompactRecoverableSignatureInvalidByteCount(got: rawRepresentation.count, expected: Self.byteCount
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
        case rsv
        
        /// `V || R || S`.
        case vrs
    }
    private var v: Data {
        Data(
            [UInt8(recoveryID.rawValue)]
        )
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

// MARK: Recovery
extension ECDSASignatureRecoverable {
    
    public enum RecoveryID: UInt8, Sendable, Hashable, Codable {
        case _0 = 0
        case _1 = 1
        case _2 = 2
        case _3 = 3
        
        internal var recid: Int32 {
            Int32(rawValue)
        }
    }
    
    public func recoverPublicKey(
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped: Bridge.ECDSA.Recovery.recover(wrapped, message: [UInt8](message))
        )
    }
}

extension ECDSASignatureRecoverable.RecoveryID {
    public init(byte: UInt8) throws {
        guard let self_ = Self(rawValue: byte) else {
            throw Bridge.Error.invalidRecoveryID(got: Int(byte))
        }
        self = self_
    }
    
    public init(recid: Int32) throws {
        guard recid <= 3 && recid >= 0 else {
            throw Bridge.Error.invalidRecoveryID(got: Int(recid))
        }
        try self.init(byte: UInt8(recid))
    }
}

// MARK: Conversion
extension ECDSASignatureRecoverable {
    public func nonRecoverable() throws -> ECDSASignatureNonRecoverable {
        try ECDSASignatureNonRecoverable(
            wrapped: Bridge.ECDSA.Recovery.nonRecoverable(self.wrapped)
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
