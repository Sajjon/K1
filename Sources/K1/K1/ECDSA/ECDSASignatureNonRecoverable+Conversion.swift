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
    
    /// `R||S` aka `X9.63` aka `IEEE P1363`
    public func p1364() throws -> Data {
        try Bridge.compactRepresentationOfSignature(rawRepresentation: _rawRepresentation)
    }
    
    public func derRepresentation() throws -> Data {
        try Bridge.derRepresentationOfSignature(rawRepresentation: _rawRepresentation)
    }
}

