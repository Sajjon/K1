//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit
import secp256k1

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
    
    public init<D: DataProtocol>(compactRepresentation: D) throws {
        var signature = secp256k1_ecdsa_signature()

//        guard secp256k1_ecdsa_signature_parse_compact(secp256k1.Context.raw, &signature, Array(compactRepresentation)).boolValue else {
//            throw secp256k1Error.underlyingCryptoError
//        }
        let compactBytes = [UInt8](compactRepresentation)
        try Bridge.call(ifFailThrow: .failedToParseSignatureFromCompactRepresentation) { context in
            secp256k1_ecdsa_signature_parse_compact(
                context,
                &signature,
                compactBytes
            )
        }

        try self.init(rawRepresentation: Data(
            bytes: &signature.data,
            count: MemoryLayout.size(ofValue: signature.data)
        ))
    }
}

extension ECDSASignatureNonRecoverable {
    internal static let byteCount = 2 * K1.Curve.Field.byteCount
    public typealias Scheme = ECDSA
    public static let scheme: SigningScheme = .ecdsa
}

