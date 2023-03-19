//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit
import FFI

public struct ECDSASignatureNonRecoverable: Sendable, Hashable {
    
    typealias Wrapped = Bridge.ECDSA.NonRecovery.Wrapped
    
    internal let wrapped: Wrapped
    
    init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
}

// MARK: Inits
extension ECDSASignatureNonRecoverable {
    public init(rawRepresentation: some DataProtocol) throws {
        // FIXME: Needed?
        //        guard
        //            rawRepresentation.count == Self.byteCount
        //        else {
        //            throw Bridge.Error.incorrectByteCountOfRawSignature
        //        }
        //
        //        self.rawRepresentation = Data(rawRepresentation)
        fatalError()
    }
    
    public init(compactRepresentation: some DataProtocol) throws {
        
        try self.init(wrapped: Bridge.ECDSA.NonRecovery.from(compactBytes: [UInt8](compactRepresentation)))
    }
    
    public init(derRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: Bridge.ECDSA.NonRecovery.from(derRepresentation: [UInt8](derRepresentation))
        )
    }
}

// MARK: Serialize
extension ECDSASignatureNonRecoverable {
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func compactRepresentation() throws -> Data {
        try Bridge.ECDSA.NonRecovery.compact(wrapped)
    }
    
    public func derRepresentation() throws -> Data {
        try Bridge.ECDSA.NonRecovery.der(wrapped)
    }
}


// MARK: Recover
extension ECDSASignatureNonRecoverable {
    public func recoverPublicKey(
        recoveryID: ECDSASignatureRecoverable.RecoveryID,
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped: Bridge.ECDSA.NonRecovery.recoverPublicKey(
                self.wrapped,
                recoveryID: recoveryID.recid,
                message: [UInt8](message)
            )
        )
        
    }
    
    
}

extension ECDSASignatureNonRecoverable {
    internal static let byteCount = Bridge.ECDSA.Recovery.byteCount
    
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
