//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

extension K1.ECDSA {
    public enum NonRecoverable {
        public typealias PrivateKey = PrivateKeyOf<Self>
        public typealias PublicKey = PrivateKey.PublicKey
    }
}

extension K1.ECDSA.NonRecoverable {
    public struct Signature: Sendable, Hashable, ContiguousBytes {
        
        typealias Wrapped = FFI.ECDSA.NonRecovery.Wrapped
        internal let wrapped: Wrapped
        
        init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}



// MARK: Inits
extension K1.ECDSA.NonRecoverable.Signature {
    
    public init(compactRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: FFI.ECDSA.NonRecovery.from(compactBytes: [UInt8](compactRepresentation))
        )
    }
    
    public init(derRepresentation: some DataProtocol) throws {
        try self.init(
            wrapped: FFI.ECDSA.NonRecovery.from(derRepresentation: [UInt8](derRepresentation))
        )
    }
}

// MARK: ContiguousBytes
extension K1.ECDSA.NonRecoverable.Signature {
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try wrapped.withUnsafeBytes(body)
    }
}

// MARK: Serialize
extension K1.ECDSA.NonRecoverable.Signature {
    
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
extension K1.ECDSA.NonRecoverable.Signature {
    public func recoverPublicKey(
        recoveryID: K1.ECDSA.Recoverable.Signature.RecoveryID,
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

extension K1.ECDSA.NonRecoverable.Signature {
    internal static let byteCount = FFI.ECDSA.Recovery.byteCount
}

// MARK: Equatable
extension K1.ECDSA.NonRecoverable.Signature {
    
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
}

// MARK: Hashable
extension K1.ECDSA.NonRecoverable.Signature {
    
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
    
}
