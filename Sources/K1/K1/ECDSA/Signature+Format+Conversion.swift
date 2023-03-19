//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-10.
//


import FFI
import Foundation

extension Bridge {
    /// Initializes ECDSASignatureNonRecoverable from the DER representation.
    static func importECDSASignature<D: DataProtocol>(fromDER derRepresentation: D) throws -> Data {
//        let derSignatureBytes = Array(derRepresentation)
//        var signatureBridgedToC = secp256k1_ecdsa_signature()
//
//        try Bridge.call(ifFailThrow: .failedToParseDERSignature) { context in
//            secp256k1_ecdsa_signature_parse_der(
//                context,
//                &signatureBridgedToC,
//                derSignatureBytes,
//                derSignatureBytes.count
//            )
//        }
//
//        let signatureData = Data(
//            bytes: &signatureBridgedToC.data,
//            count: MemoryLayout.size(ofValue: signatureBridgedToC.data)
//        )
//
//        return signatureData
        fatalError()
    }
    
    static func compactRepresentationOfSignature(rawRepresentation: Data) throws -> Data {
        
//        let compactSignatureLength = 64
//        var signatureBridgedToC = secp256k1_ecdsa_signature()
//        var compactSignature = [UInt8](repeating: 0, count: compactSignatureLength)
//
//        withUnsafeMutableBytes(of: &signatureBridgedToC.data) { pointer in
//            pointer.copyBytes(from: rawRepresentation.prefix(pointer.count))
//        }
//
//
//        try Bridge.call(ifFailThrow: .failedToSerializeCompactSignature) { context in
//            secp256k1_ecdsa_signature_serialize_compact(
//                context,
//                &compactSignature,
//                &signatureBridgedToC
//            )
//
//        }
//
//        return Data(compactSignature)
        fatalError()
    }
    

}
