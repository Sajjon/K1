//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

// Bridge to C
import secp256k1
import Foundation

extension ECDSASignatureNonRecoverable {
    /// Initializes ECDSASignatureNonRecoverable from the DER representation.
    public static func `import`<D: DataProtocol>(fromDER derRepresentation: D) throws -> Self {
        let signatureData = try Bridge.importECDSASignature(fromDER: derRepresentation)
        return try Self(rawRepresentation: signatureData)
    }
    

    
    public func compactRepresentation() throws -> Data {
        try Bridge.compactRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
    
    public func derRepresentation() throws -> Data {
        try Bridge.derRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
}

