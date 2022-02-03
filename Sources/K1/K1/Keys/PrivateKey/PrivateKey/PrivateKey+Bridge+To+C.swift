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
        message: [UInt8],
        privateKey: SecureBytes,
        mode: ECDSASignature.SigningMode
    ) throws -> Data {
        
        guard message.count == K1.Curve.Field.byteCount else {
            throw K1.Error.incorrectByteCountOfMessageToECDSASign
        }
        
        if let nonceFunctionArbitraryData = mode.nonceFunctionArbitraryData {
            guard nonceFunctionArbitraryData.count == 32 else {
                throw K1.Error.incorrectByteCountOfArbitraryDataForNonceFunction
            }
        }
        
        var nonceFunctionArbitraryBytes: [UInt8]? = nil
        if let nonceFunctionArbitraryData = mode.nonceFunctionArbitraryData {
            guard nonceFunctionArbitraryData.count == K1.Curve.Field.byteCount else {
                throw K1.Error.incorrectByteCountOfArbitraryDataForNonceFunction
            }
            nonceFunctionArbitraryBytes = [UInt8](nonceFunctionArbitraryData)
        }
                
        var signatureBridgedToC = secp256k1_ecdsa_signature()
        
        try Self.call(
            ifFailThrow: .failedToECDSASignDigest
        ) { context in
            secp256k1_ecdsa_sign(
                context,
                &signatureBridgedToC,
                message,
                privateKey.backing.bytes,
                secp256k1_nonce_function_rfc6979,
                nonceFunctionArbitraryBytes
            )
        }

        return Data(
            bytes: &signatureBridgedToC.data,
            count: MemoryLayout.size(ofValue: signatureBridgedToC.data)
        )
    }
    
    static func schnorrSign(
        message: [UInt8],
        privateKey: SecureBytes,
        input: SchnorrInput?
    ) throws -> Data {
        guard message.count == K1.Curve.Field.byteCount else {
            throw K1.Error.failedToSchnorrSignMessageInvalidLength
        }
        var signatureOut = [UInt8](repeating: 0, count: 64)
        
        var keyPair = secp256k1_keypair()

        try Self.call(
            ifFailThrow: .failedToInitializeKeyPairForSchnorrSigning
        ) { context in
            secp256k1_keypair_create(context, &keyPair, privateKey.backing.bytes)
        }
        
        var auxilaryRandomBytes: [UInt8]? = nil
        if let auxilaryRandomData = input?.auxilaryRandomData {
            guard auxilaryRandomData.count == K1.Curve.Field.byteCount else {
                throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
            }
            auxilaryRandomBytes = [UInt8](auxilaryRandomData)
        }
        
        try Self.call(
            ifFailThrow: .failedToSchnorrSignDigest
        ) { context in
            secp256k1_schnorrsig_sign(
                context,
                &signatureOut,
                message,
                &keyPair,
                auxilaryRandomBytes
            )
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
            secp256k1_schnorrsig_verify(context, &signatureOut, message, message.count, &publicKey)
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


public struct SchnorrInput {
    public let auxilaryRandomData: Data
}

internal extension K1.PrivateKey {

    func ecdsaSign<D: DataProtocol>(
        hashed message: D,
        mode: ECDSASignature.SigningMode = .default
    ) throws -> ECDSASignature {
        let messageBytes = [UInt8](message)
        let signatureData = try withSecureBytes { (secureBytes: SecureBytes) -> Data in
            try Bridge.ecdsaSign(message: messageBytes, privateKey: secureBytes, mode: mode)
        }

        return try ECDSASignature(
            rawRepresentation: signatureData
        )
    }
    
    func schnorrSign<D: DataProtocol>(
        hashed: D,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        let message = [UInt8](hashed)
        let signatureData = try withSecureBytes { (secureBytes: SecureBytes) -> Data in
            try Bridge.schnorrSign(message: message, privateKey: secureBytes, input: maybeInput)
        }

        return try SchnorrSignature(
            rawRepresentation: signatureData
        )
    }
}

public extension K1.PrivateKey {

    func ecdsaSign<D: Digest>(
        digest: D,
        mode: ECDSASignature.SigningMode = .default
    ) throws -> ECDSASignature {
        try ecdsaSign(hashed: Array(digest), mode: mode)
    }
    
    func ecdsaSign<D: DataProtocol>(
        unhashed data: D,
        mode: ECDSASignature.SigningMode = .default
    ) throws -> ECDSASignature {
        try ecdsaSign(digest: SHA256.hash(data: data), mode: mode)
    }
    
    
    func schnorrSign<D: Digest>(
        digest: D,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try schnorrSign(hashed: Array(digest), input: maybeInput)
    }
    
    func schnorrSign<D: DataProtocol>(
        unhashed data: D,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try schnorrSign(digest: SHA256.hash(data: data), input: maybeInput)
    }
    
  
    func sign<S: SignatureScheme, D: DataProtocol>(
        hashed: D,
        scheme: S.Type,
        mode: S.Signature.SigningMode
    ) throws -> S.Signature {
        try S.Signature.by(signing: hashed, with: self, mode: mode)
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
