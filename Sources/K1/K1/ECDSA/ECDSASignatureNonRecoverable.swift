//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

@available(*, deprecated, message: "'ECDSASignature' is a deprecated typealias for 'ECDSASignatureNonRecoverable', use 'ECDSASignatureNonRecoverable' or ECDSASignatureRecovarable' instead.")
public typealias ECDSASignature = ECDSASignatureNonRecoverable

public struct ECDSASignatureNonRecoverable: Sendable, Hashable, ECSignature {
    
    public typealias Scheme = ECDSA
   
    internal let _rawRepresentation: Data
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
       
        guard
            rawRepresentation.count == Self.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self._rawRepresentation = Data(rawRepresentation)
    }
}

internal extension ECDSASignatureNonRecoverable {
    static let byteCount = 2 * K1.Curve.Field.byteCount
}

public extension ECDSASignatureNonRecoverable {
    static let scheme: SigningScheme = .ecdsa
//    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
//        try self.rawRepresentation.withUnsafeBytes(body)
//    }
    
}

