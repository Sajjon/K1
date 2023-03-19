//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation
import secp256k1

enum Raw {}

extension Raw {
    
    static func recoverableSignature(
        _ rawRepresentation: some DataProtocol
    ) throws -> secp256k1_ecdsa_recoverable_signature {
        let expected = 65
        guard
            rawRepresentation.count == expected
        else {
            throw Bridge.Error.incorrectByteCountOfRawRecoverableSignature(
                got: rawRepresentation.count,
                expected: expected
            )
        }
        var raw = secp256k1_ecdsa_recoverable_signature()
        withUnsafeMutableBytes(of: &raw.data) { pointer in
            pointer.copyBytes(
                from: rawRepresentation.prefix(pointer.count)
            )
        }
        return raw
    }
    
    static func nonRecoverableSignature(
        compactBytes: [UInt8]
    ) throws -> secp256k1_ecdsa_signature {
       
        var raw = secp256k1_ecdsa_signature()
       
        try Bridge.call(ifFailThrow: .failedToParseNonRecoverableSignatureFromCompactRepresentation) { context in
            secp256k1_ecdsa_signature_parse_compact(
                context,
                &raw,
                compactBytes
            )
        }
        
        return raw
    }
    
    static func nonRecoverableSignature(
        derBytes: [UInt8]
    ) throws -> secp256k1_ecdsa_signature {
       
        var raw = secp256k1_ecdsa_signature()
       
        try Bridge.call(ifFailThrow: .failedToParseNonRecoverableSignatureFromCompactRepresentation) { context in
            secp256k1_ecdsa_signature_parse_der(
                context,
                &raw,
                derBytes,
                derBytes.count
            )
        }
        
        return raw
    }
}
