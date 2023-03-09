//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

public typealias ECDSASignature = ECDSASignatureNonRecoverable

public struct ECDSASignatureNonRecoverable: ContiguousBytes, Sendable, Hashable, ECSignature {
    
    public typealias Scheme = ECDSA
   
    private let _rawRepresentation: [UInt8]
    public var rawRepresentation: Data {
        Data(_rawRepresentation)
    }
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
       
        guard
            rawRepresentation.count == Self.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self._rawRepresentation = [UInt8](rawRepresentation)
    }
}

internal extension ECDSASignatureNonRecoverable {
    static let byteCount = 2 * K1.Curve.Field.byteCount
}

public extension ECDSASignatureNonRecoverable {
    static let scheme: SigningScheme = .ecdsa
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.rawRepresentation.withUnsafeBytes(body)
    }
    
}

