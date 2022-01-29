//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import secp256k1

extension Bridge {
    
    static func ecdsaSign(
        digest: [UInt8],
        privateKey: SecureBytes
    ) throws -> Data {
        var signatureBridgedToC = secp256k1_ecdsa_signature()
        
        try Self.call(
            ifFailThrow: .failedToSignDigest
        ) { context in
            secp256k1_ecdsa_sign(
                context,
                &signatureBridgedToC,
                digest,
                privateKey.backing.bytes,
                nil,
                nil
            )
        }
        
        return Data(
            bytes: &signatureBridgedToC.data,
            count: MemoryLayout.size(ofValue: signatureBridgedToC.data)
        )
    }
}

public extension K1.PrivateKey {

    func signature<D: Digest>(for digest: D) throws -> ECDSASignature {
        let signatureData = try withSecureBytes { secureBytes in
            try Bridge.ecdsaSign(digest: Array(digest), privateKey: secureBytes)
        }
        
        return try ECDSASignature(
            signatureData
        )
    }
}
