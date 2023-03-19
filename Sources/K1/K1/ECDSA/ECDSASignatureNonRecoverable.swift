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
    
    typealias Wrapped = Bridge.ECDSA.NonRecovery.Wrapped
    internal let wrapped: Wrapped
    init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
    
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
    
    public func compactRepresentation() throws -> Data {
        try Bridge.ECDSA.NonRecovery.compact(wrapped)
    }
    
    internal var rawRepresentation: Data {
        Data(wrapped.bytes)
    }
    
    public func derRepresentation() throws -> Data {
        try Bridge.ECDSA.NonRecovery.der(wrapped)
    }
    
    public func recoverPublicKey(
        recoveryID: ECDSASignatureRecoverable.RecoveryID,
        message: some DataProtocol
    ) throws -> K1.PublicKey {
        try K1.PublicKey(
            wrapped:  Bridge.ECDSA.NonRecovery.recoverPublicKey(self.wrapped, recoveryID: recoveryID.rawValue, message: [UInt8](message))
        )
       
    }
    

}

extension ECDSASignatureNonRecoverable {
    internal static let byteCount = Bridge.ECDSA.Recovery.byteCount

}

