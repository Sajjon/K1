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
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
    
 
//    public let rawRepresentation: Data
    typealias Wrapped = Bridge.ECDSA.Recovery.Wrapped
    private let wrapped: Wrapped
    
    internal init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
    
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
    

    public init<D: DataProtocol>(rawRepresentation: D) throws {
        try self.init(wrapped: Bridge.ECDSA.Recovery.from(rawRepresentation: rawRepresentation))
    }
    
    public func recoverPublicKey(
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped: Bridge.ECDSA.Recovery.recover(wrapped, message: [UInt8](message))
        )
    }
}

extension ECDSASignatureRecoverable {
    
    public func nonRecoverable() throws -> ECDSASignatureNonRecoverable {
        try ECDSASignatureNonRecoverable(
            wrapped: Bridge.ECDSA.Recovery.nonRecoverable(self.wrapped)
        )
    }
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func compact(
        format: RecoverableSignatureSerializationFormat
    ) throws -> Compact {
        
        let (rs, recoveryID) = try Bridge.ECDSA.Recovery.serialize(
            wrapped,
            format: format
        )
        
        return .init(
            rs: Data(rs),
            recoveryID: .init(recoveryID)
        )
    }
    
    public struct Compact: Sendable, Hashable {
        public let rs: Data
        public let recoveryID: RecoveryID
    }
    public typealias RecoveryID = Tagged<Self, Int32>
}

