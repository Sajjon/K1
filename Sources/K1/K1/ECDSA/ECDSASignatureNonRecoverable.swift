//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

public struct ECDSASignatureNonRecoverable: Sendable, Hashable, ECSignature {
    
    public let rawRepresentation: Data
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
        guard
            rawRepresentation.count == Self.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self.rawRepresentation = Data(rawRepresentation)
    }
}

extension ECDSASignatureNonRecoverable {
    internal static let byteCount = 2 * K1.Curve.Field.byteCount
    public typealias Scheme = ECDSA
    public static let scheme: SigningScheme = .ecdsa
}

