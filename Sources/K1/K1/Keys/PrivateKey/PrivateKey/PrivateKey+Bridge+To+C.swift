//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import secp256k1
import CryptoKit
import Foundation

struct IncorrectByteCount: Swift.Error {}
public func swapSignatureByteOrder<D>(_ data: D) throws -> Data where D: DataProtocol {
    guard data.count == 64 || data.count == 65 else {
        throw IncorrectByteCount()
    }
    let invalidByteOrder = Data(data)
    let r = Data(invalidByteOrder[0 ..< 32].reversed())
    let s = Data(invalidByteOrder[32 ..< 64].reversed())
    
    var vDataOrEmpty = Data()
    if data.count > 64 {
        vDataOrEmpty = Data([invalidByteOrder[64]])
    }

    return vDataOrEmpty + r + s
}

extension Bridge {
    
    /// Produces a **recoverable** ECDSA signature.
    static func ecdsaSignRecoverable(
        message: [UInt8],
        privateKey: SecureBytes,
        mode: ECDSASignatureNonRecoverable.SigningMode
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
                
        var signatureRecoverableBridgedToC = secp256k1_ecdsa_recoverable_signature()
        
        try Self.call(
            ifFailThrow: .failedToECDSASignDigest
        ) { context in
            secp256k1_ecdsa_sign_recoverable(
                context,
                &signatureRecoverableBridgedToC,
                message,
                privateKey.backing.bytes,
                secp256k1_nonce_function_rfc6979,
                nonceFunctionArbitraryBytes
            )
        }

        return Data(
            bytes: &signatureRecoverableBridgedToC.data,
            count: MemoryLayout.size(ofValue: signatureRecoverableBridgedToC.data)
        )
    }
    
    /// Produces a **non recoverable** ECDSA signature.
    static func ecdsaSignNonRecoverable(
        message: [UInt8],
        privateKey: SecureBytes,
        mode: ECDSASignatureNonRecoverable.SigningMode
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
            secp256k1_schnorrsig_sign32(
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

        try Self.call(ifFailThrow: .incorrectByteCountOfPublicKey(providedByteCount: publicKeyBytes.count)) { context in
            /* Parse a variable-length public key into the pubkey object. */
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
    
    static func convertToNonRecoverable(
        ecdsaSignature: ECDSASignatureRecoverable
    ) throws -> ECDSASignatureNonRecoverable {
        var recoverableBridgedToC = secp256k1_ecdsa_recoverable_signature()
        let rs = [UInt8](ecdsaSignature.rs())
        try Self.call(
            ifFailThrow: .failedToParseRecoverableSignatureFromECDSASignature
        ) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &recoverableBridgedToC,
                rs,
                Int32(ecdsaSignature.recoveryID)
            )
        }
        
        var nonRecoverableBridgedToC = secp256k1_ecdsa_signature()
        
        try Self.call(
            ifFailThrow: .failedToConvertRecoverableSignatureToNonRecoverable
        ) { context in
            secp256k1_ecdsa_recoverable_signature_convert(
                context,
                &nonRecoverableBridgedToC,
                &recoverableBridgedToC
            )
        }
        
        let signatureData = Data(
            bytes: &nonRecoverableBridgedToC.data,
            count: MemoryLayout.size(ofValue: nonRecoverableBridgedToC.data)
        )
        
        return try ECDSASignatureNonRecoverable(rawRepresentation: signatureData)
    }
    
    /// Recover an ECDSA public key from a non recoverable signature using recovery ID
    static func recoverPublicKey(
        ecdsaSignature: ECDSASignatureNonRecoverable,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> [UInt8] {
        try _recoverPublicKey(
            rs: ecdsaSignature.p1364(),
            recoveryID: recoveryID,
            message: message
        )
    }
    
    /// Recover an ECDSA public key from a signature.
    static func recoverPublicKey(
        ecdsaSignature: ECDSASignatureRecoverable,
        message: [UInt8]
    ) throws -> [UInt8] {
        try _recoverPublicKey(
            rs: ecdsaSignature.rs(),
            recoveryID: Int32(ecdsaSignature.recoveryID),
            message: message
        )
    }

    /// Recover an ECDSA public key from a signature.
    static func _recoverPublicKey(
        rs rsData: Data,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> [UInt8] {
        var signatureBridgedToC = secp256k1_ecdsa_recoverable_signature()
        let rs = [UInt8](rsData)
        try Self.call(
            ifFailThrow: .failedToParseRecoverableSignatureFromECDSASignature
        ) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &signatureBridgedToC,
                rs,
                recoveryID
            )
        }
        
        var publicKeyBridgedToC = secp256k1_pubkey()
        try Self.call(
            ifFailThrow: .failedToRecoverPublicKeyFromSignature
        ) { context in
            secp256k1_ecdsa_recover(
                context,
                &publicKeyBridgedToC,
                &signatureBridgedToC,
                message
            )
        }
        let publicKeyFormat = K1.Format.uncompressed
        var publicPointBytes = [UInt8](
            repeating: 0,
            count: publicKeyFormat.length
        )
        var pubkeyBytesSerializedCount = publicKeyFormat.length
        try publicPointBytes.withUnsafeMutableBytes { pubkeyBytes in
            try Self.call(
                ifFailThrow: .failedToSerializePublicKeyIntoBytes
            ) { context in
               secp256k1_ec_pubkey_serialize(
                context,
                pubkeyBytes.baseAddress!,
                &pubkeyBytesSerializedCount,
                &publicKeyBridgedToC,
                publicKeyFormat.rawValue
               )
            }
        }
        guard
            pubkeyBytesSerializedCount == K1.Format.uncompressed.length,
            publicPointBytes.count == K1.Format.uncompressed.length
        else {
            throw K1.Error.failedToSerializePublicKeyIntoBytes
        }
  
        return publicPointBytes
    }
}


public struct SchnorrInput {
    public let auxilaryRandomData: Data
}

public extension ECDSASignatureRecoverable {
    
    /// `recoverID` is optional since `self` can contain the recoveryID already.
    func recoverPublicKey<D: DataProtocol>(
        messageThatWasSigned: D
    ) throws -> K1.PublicKey {
        let uncompressedPublicKeyBytes = try Bridge.recoverPublicKey(
            ecdsaSignature: self,
            message: [UInt8](messageThatWasSigned)
        )
        let publicKey = try K1.PublicKey(
            wrapped: .init(uncompressedRaw: uncompressedPublicKeyBytes)
        )
        
        guard try publicKey.isValid(signature: self.nonRecoverable(), hashed: messageThatWasSigned) else {
            throw K1.Error.expectedPublicKeyToBeValidForSignatureAndMessage
        }
        
        return publicKey
    }
}

public extension ECDSASignatureNonRecoverable {
    
    /// `recoverID` is optional since `self` can contain the recoveryID already.
    func recoverPublicKey<D: DataProtocol>(
        recoveryID: Int,
        messageThatWasSigned: D
    ) throws -> K1.PublicKey {
        let uncompressedPublicKeyBytes = try Bridge.recoverPublicKey(
            ecdsaSignature: self,
            recoveryID: Int32(recoveryID),
            message: [UInt8](messageThatWasSigned)
        )
        let publicKey = try K1.PublicKey(
            wrapped: .init(uncompressedRaw: uncompressedPublicKeyBytes)
        )
        
//        guard try publicKey.isValid(signature: self, hashed: messageThatWasSigned) else {
//            throw K1.Error.expectedPublicKeyToBeValidForSignatureAndMessage
//        }
        
        return publicKey
    }
}

public extension K1.PrivateKey {

    /// Produces a **recoverable** ECDSA signature.
    func ecdsaSignRecoverable<D: DataProtocol>(
        hashed message: D,
        mode: ECDSASignatureNonRecoverable.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        let messageBytes = [UInt8](message)
        let signatureData = try withSecureBytes { (secureBytes: SecureBytes) -> Data in
            try Bridge.ecdsaSignRecoverable(message: messageBytes, privateKey: secureBytes, mode: mode)
        }

        return try ECDSASignatureRecoverable(
            rawRepresentation: signatureData
        )
    }
    
    /// Produces a **non recoverable** ECDSA signature.
    func ecdsaSignNonRecoverable<D: DataProtocol>(
        hashed message: D,
        mode: ECDSASignatureNonRecoverable.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        let messageBytes = [UInt8](message)
        let signatureData = try withSecureBytes { (secureBytes: SecureBytes) -> Data in
            try Bridge.ecdsaSignNonRecoverable(message: messageBytes, privateKey: secureBytes, mode: mode)
        }

        return try ECDSASignatureNonRecoverable(
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

    func ecdsaSignNonRecoverable<D: Digest>(
        digest: D,
        mode: ECDSASignatureNonRecoverable.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        try ecdsaSignNonRecoverable(hashed: Array(digest), mode: mode)
    }
    
    func ecdsaSignNonRecoverable<D: DataProtocol>(
        unhashed data: D,
        mode: ECDSASignatureNonRecoverable.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        try ecdsaSignNonRecoverable(digest: SHA256.hash(data: data), mode: mode)
    }
    
    func ecdsaSignRecoverable<D: Digest>(
        digest: D,
        mode: ECDSASignatureNonRecoverable.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ecdsaSignRecoverable(hashed: Array(digest), mode: mode)
    }
    
    func ecdsaSignRecoverable<D: DataProtocol>(
        unhashed data: D,
        mode: ECDSASignatureNonRecoverable.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ecdsaSignRecoverable(digest: SHA256.hash(data: data), mode: mode)
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
    
  
    func sign<S: ECSignatureScheme, D: DataProtocol>(
        hashed: D,
        scheme: S.Type,
        mode: S.Signature.SigningMode
    ) throws -> S.Signature {
        try S.Signature.by(signing: hashed, with: self, mode: mode)
    }
    
    func sign<S: ECSignatureScheme>(
        digest: S.HashDigest,
        scheme: S.Type,
        mode: S.Signature.SigningMode
    ) throws -> S.Signature {
        try S.Signature.by(signing: Array(digest), with: self, mode: mode)
    }
    
      func sign<S: ECSignatureScheme, D: DataProtocol>(
          unhashed: D,
          scheme: S.Type,
          mode: S.Signature.SigningMode
      ) throws -> S.Signature {
          try sign(
            hashed: Data(S.hash(unhashed: unhashed)),
            scheme: scheme,
            mode: mode
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
            try Bridge.ecdh(publicKey: publicKeyShare.uncompressedRaw, privateKey: secureBytes)
        }
        return sharedSecretData
    }
}
