//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

public struct ECDSASignatureNonRecoverable: Sendable, Hashable {
    
    typealias Wrapped = FFI.ECDSA.NonRecovery.Wrapped
    internal let wrapped: Wrapped
    
    init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
}

// MARK: Inits
extension ECDSASignatureNonRecoverable {
    
    public init(compactRepresentation: some DataProtocol) throws {
        
        try self.init(wrapped: FFI.ECDSA.NonRecovery.from(compactBytes: [UInt8](compactRepresentation)))
    }
    
    public init(derRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: FFI.ECDSA.NonRecovery.from(derRepresentation: [UInt8](derRepresentation))
        )
    }
}

// MARK: Serialize
extension ECDSASignatureNonRecoverable {
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func compactRepresentation() throws -> Data {
        try FFI.ECDSA.NonRecovery.compact(wrapped)
    }
    
    public func derRepresentation() throws -> Data {
        try FFI.ECDSA.NonRecovery.der(wrapped)
    }
}


// MARK: Recover
extension ECDSASignatureNonRecoverable {
    public func recoverPublicKey(
        recoveryID: ECDSASignatureRecoverable.RecoveryID,
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped: FFI.ECDSA.NonRecovery.recoverPublicKey(
                self.wrapped,
                recoveryID: recoveryID.recid,
                message: [UInt8](message)
            )
        )
    }
}

extension ECDSASignatureNonRecoverable {
    internal static let byteCount = FFI.ECDSA.Recovery.byteCount
}

// MARK: Equatable
extension ECDSASignatureNonRecoverable {
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
}

// MARK: Hashable
extension ECDSASignatureNonRecoverable {
    
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
    
}
