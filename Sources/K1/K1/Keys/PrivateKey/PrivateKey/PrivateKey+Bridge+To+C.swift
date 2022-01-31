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
    
    static func ecdh(
        publicKey publicKeyBytes: [UInt8],
        privateKey: SecureBytes
    ) throws -> Data {

        var publicKeyBridgedToC = secp256k1_pubkey()

        try Self.call(ifFailThrow: .failedToSerializePublicKeyIntoBytes) { context in
            /* "Serialize a pubkey object into a serialized byte sequence." */
            secp256k1_ec_pubkey_parse(
                context,
                &publicKeyBridgedToC,
                publicKeyBytes,
                publicKeyBytes.count
            )
        }

        var sharedPublicPointBytes = [UInt8](
            repeating: 0,
            count: K1.Format.uncompressed.length
        )
        
        try Self.call(
            ifFailThrow: .failedToPerformDiffieHellmanKeyExchange
        ) { context in
            /** Compute an EC Diffie-Hellman secret in constant time
             */
            secp256k1_ecdh(
                context,
                &sharedPublicPointBytes, // output
                &publicKeyBridgedToC, // pubkey
                privateKey.backing.bytes, // seckey
                ecdh_skip_hash_extract_x_and_y, // hashfp
                nil // arbitrary data pointer that is passed through to hashfp
            )
        }
        return Data(sharedPublicPointBytes)
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
    
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns the public point obtain by performing EC mult between
    ///  this `privateKey` and `publicKeyShare`
    /// - Throws: An error occurred while computing the shared secret
    func sharedSecret(with publicKeyShare: K1.PublicKey) throws -> Data {
        let sharedSecretData = try withSecureBytes { secureBytes in
            try Bridge.ecdh(publicKey: publicKeyShare.rawRepresentation, privateKey: secureBytes)
        }
        return sharedSecretData
    }
}
