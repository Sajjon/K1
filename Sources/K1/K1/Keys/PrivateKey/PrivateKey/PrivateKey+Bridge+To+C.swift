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
            ifFailThrow: .failedToECDSASignDigest
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
    
    static func schnorrSign(
        digest: [UInt8],
        privateKey: SecureBytes,
        nonce: [UInt8]?
    ) throws -> Data {
        var signatureOut = [UInt8].init(repeating: 0, count: 64)
        
        var keyPair = secp256k1_keypair()
        
        if let nonce = nonce {
            guard nonce.count == 32 else {
                throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
            }
        }
        
        try Self.call(
            ifFailThrow: .failedToInitializeKeyPairForSchnorrSigning
        ) { context in
            secp256k1_keypair_create(context, &keyPair, privateKey.backing.bytes)
        }
        
        try Self.call(
            ifFailThrow: .failedToSchnorrSignDigest
        ) { context in
            /*
             *  Does _not_ strictly follow BIP-340 because it does not verify the resulting
             *  signature. Instead, you can manually use secp256k1_schnorrsig_verify and
             *  abort if it fails.
             
             `aux_rand32`: 32 bytes of fresh randomness. While recommended to provide
          *                this, it is only supplemental to security and can be NULL. A
          *                NULL argument is treated the same as an all-zero one. See
          *                BIP-340 "Default Signing" for a full explanation of this
          *                argument and for guidance if randomness is expensive.
             */
            
            secp256k1_schnorrsig_sign(context, &signatureOut, digest, &keyPair, nonce)
        }
        
        var publicKey = secp256k1_xonly_pubkey()
        
        try Self.call(
            ifFailThrow: .failedToSchnorrSignErrorGettingPubKeyFromKeyPair
        ) { context in
            secp256k1_keypair_xonly_pub(context, &publicKey, nil, &keyPair)
        }
        
        try Self.call(
            ifFailThrow: .failedToSchnorrSignDigestDidNotPassVerification
        ) { context in
            secp256k1_schnorrsig_verify(context, &signatureOut, digest, digest.count, &publicKey)
        }

        return Data(signatureOut)
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

public extension K1 {
    enum SignatureScheme {
        case ecdsa
        case schnorr(nonce: [UInt8]?)
    }
}

internal extension K1.PrivateKey {
    
    func signature<D: DataProtocol>(
        alreadyHashed digest: D,
        scheme: K1.SignatureScheme = .ecdsa
    ) throws -> ECDSASignature {
        let digestBytes = [UInt8](digest)
        precondition(digestBytes.count == K1.Curve.Field.byteCount)
        let signatureData = try withSecureBytes { (secureBytes: SecureBytes) -> Data in
            switch scheme {
            case .ecdsa:
                return try Bridge.ecdsaSign(digest: digestBytes, privateKey: secureBytes)
            case .schnorr(let maybeNonce):
                return try Bridge.schnorrSign(digest: digestBytes, privateKey: secureBytes, nonce: maybeNonce)
            }
          
        }
        
        return try ECDSASignature(
            signatureData
        )
    }
}

public extension K1.PrivateKey {

    func signature<D: Digest>(
        for digestBytes: D,
        scheme: K1.SignatureScheme = .ecdsa
    ) throws -> ECDSASignature {
        try signature(alreadyHashed: Array(digestBytes))
    }
    
    
    func signature<D: DataProtocol>(
        for data: D,
        scheme: K1.SignatureScheme = .ecdsa
    ) throws -> ECDSASignature {
        try self.signature(for: SHA256.hash(data: data), scheme: scheme)
    }

    
    /// Performs a key agreement with provided public key share.
    ///
    /// - Parameter publicKeyShare: The public key to perform the ECDH with.
    /// - Returns: Returns the public point obtain by performing EC mult between
    ///  this `privateKey` and `publicKeyShare`
    /// - Throws: An error occurred while computing the shared secret
    func sharedSecret(with publicKeyShare: K1.PublicKey) throws -> Data {
        let sharedSecretData = try withSecureBytes { secureBytes in
            try Bridge.ecdh(publicKey: publicKeyShare.uncompressedRaw, privateKey: secureBytes)
        }
        return sharedSecretData
    }
}
