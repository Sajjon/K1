//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import secp256k1
import CryptoKit
import Foundation

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
    
    enum ECDHSerializeFunction {
        
        /// Using the `libsecp256k1` default behaviour, which is to SHA256 hash the compressed public key
        case libsecp256kDefault
        
        /// Following the [ANSI X9.63][ansix963] standard
        ///
        /// [ansix963]: https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
        case ansiX963
        
        /// Following no standard at all, does not hash the shared public point, and returns it in full.
        case noHashWholePoint
        
        func hashfp() -> (Optional<@convention(c) (Optional<UnsafeMutablePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafeMutableRawPointer>) -> Int32>) {
            switch self {
            case .libsecp256kDefault: return secp256k1_ecdh_hash_function_default
            case .ansiX963: return ecdh_skip_hash_extract_only_x
            case .noHashWholePoint: return ecdh_skip_hash_extract_x_and_y
            }
        }
        
        var outputByteCount: Int {
            switch self {
            case .libsecp256kDefault: return K1.Curve.Field.byteCount
            case .ansiX963: return K1.Curve.Field.byteCount
            case .noHashWholePoint: return K1.Format.uncompressed.length
            }
        }
    }
    
    static func ecdh(
        publicKey publicKeyBytes: [UInt8],
        privateKey: SecureBytes,
        hashFp: ECDHSerializeFunction
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
            count: hashFp.outputByteCount
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
                hashFp.hashfp(), // hashfp
                nil // arbitrary data pointer that is passed through to hashfp
            )
        }
        return Data(sharedPublicPointBytes)
    }
    
    static func convertToNonRecoverable(
        ecdsaSignature: ECDSASignatureRecoverable
    ) throws -> ECDSASignatureNonRecoverable {
        var recoverableBridgedToC = secp256k1_ecdsa_recoverable_signature()
        
        withUnsafeMutableBytes(of: &recoverableBridgedToC.data) { pointer in
            pointer.copyBytes(
                from: ecdsaSignature.rawRepresentation.prefix(pointer.count)
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
            rs: ecdsaSignature.compactRepresentation(),
            recoveryID: recoveryID,
            message: message
        )
    }
    
    /// Recover an ECDSA public key from a signature.
    static func recoverPublicKey(
        ecdsaSignature: ECDSASignatureRecoverable,
        message: [UInt8]
    ) throws -> [UInt8] {
        var recoverableBridgedToC = secp256k1_ecdsa_recoverable_signature()
        
        withUnsafeMutableBytes(of: &recoverableBridgedToC.data) { pointer in
            pointer.copyBytes(
                from: ecdsaSignature.rawRepresentation.prefix(pointer.count)
            )
        }
        
        return try __recoverPubKeyFrom(
            signatureBridgedToC: recoverableBridgedToC,
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
        
        return try __recoverPubKeyFrom(
            signatureBridgedToC: signatureBridgedToC,
            message: message
        )
    }
    
    static func __recoverPubKeyFrom(
        signatureBridgedToC: secp256k1_ecdsa_recoverable_signature,
        message: [UInt8]
    ) throws -> [UInt8] {
        var signatureBridgedToC = signatureBridgedToC
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
        
        guard try publicKey.isValid(signature: self, hashed: messageThatWasSigned) else {
            throw K1.Error.expectedPublicKeyToBeValidForSignatureAndMessage
        }
        
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
        let raw = try withSecureBytes {
            try Bridge.ecdsaSignRecoverable(message: messageBytes, privateKey: $0, mode: mode)
        }
        
        return try ECDSASignatureRecoverable.init(rawRepresentation: raw)
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
}

/// MARK: ECDH
extension K1.PrivateKey {
    
    private func _ecdh(
        publicKey: K1.PublicKey,
        serializeOutputFunction hashFp: Bridge.ECDHSerializeFunction
    ) throws -> Data {
        let sharedSecretData = try withSecureBytes { secureBytes in
            try Bridge.ecdh(
                publicKey: publicKey.uncompressedRaw,
                privateKey: secureBytes,
                hashFp: hashFp
            )
        }
        return sharedSecretData
    }
    
  

    /// Computes a shared secret with the provided public key from another party,
    /// returning only the `X` coordinate of the point, following [ANSI X9.63][ansix963] standards.
    ///
    /// This is one of three ECDH functions, this library vendors, all three versions
    /// uses different serialization of the shared EC Point, specifically:
    /// 1. SHA-256 hash the compressed point
    /// 2. No hash, return point uncompressed
    /// 3. No hash, return only the `X` coordinate of the point <- this function
    ///
    /// This function uses 3. i.e. no hash, and returns only the `X` coordinate of the point.
    /// This is following the [ANSI X9.63][ansix963] standard serialization of the shared point.
    ///
    /// Further more this function is compatible with CryptoKit, since it returns a CryptoKit
    /// `SharedSecret` struct, thus offering you to use all of CryptoKit's Key Derivation Functions
    /// (`KDF`s), which can be called on the `SharedSecret`.
    ///
    /// As seen on [StackExchange][cryptostackexchange], this version is compatible with the following
    /// libraries:
    /// - JS: `elliptic` (v6.4.0 in nodeJS v8.2.1)
    /// - JS: `crypto` (builtin) - uses openssl under the hood (in nodeJS v8.2.1)
    /// - .NET: `BouncyCastle` (BC v1.8.1.3, .NET v2.1.4)
    ///
    /// [ansix963]: https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
    /// [cryptostackexchange]: https://crypto.stackexchange.com/a/57727
    public func sharedSecretFromKeyAgreement(
        with publicKeyShare: K1.PublicKey
    ) throws -> SharedSecret {
        let sharedSecretData =  try _ecdh(publicKey: publicKeyShare, serializeOutputFunction: .ansiX963)
        let __sharedSecret = __SharedSecret(ss: .init(bytes: sharedSecretData))
        let sharedSecret = unsafeBitCast(__sharedSecret, to: SharedSecret.self)
        guard sharedSecret.withUnsafeBytes({ Data($0).count == sharedSecretData.count }) else {
            throw K1.Error.failedToProduceSharedSecret
        }
        return sharedSecret
    }
    
    /// Computes a shared secret with the provided public key from another party,
    /// using `libsecp256k1` default behaviour, returning a hashed of the compressed point.
    ///
    /// This is one of three ECDH functions, this library vendors, all three versions
    /// uses different serialization of the shared EC Point, specifically:
    /// 1. SHA-256 hash the compressed point <- this function
    /// 2. No hash, return point uncompressed
    /// 3. No hash, return only the `X` coordinate of the point.
    ///
    /// This function uses 1. i.e.SHA-256 hash the compressed point.
    /// This is using the [default behaviour of `libsecp256k1`][libsecp256k1], which does not adhere to any
    /// other standard.
    ///
    /// As seen on [StackExchange][cryptostackexchange], this version is compatible with all
    /// libraries which wraps `libsecp256k1`, e.g.:
    /// - Python wrapper: secp256k1 (v0.13.2, for python 3.6.4)
    /// - JS wrapper: secp256k1 (v3.5.0, for nodeJS v8.2.1)
    ///
    /// [libsecp256k1]: https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/ecdh/main_impl.h#L27
    /// [cryptostackexchange]: https://crypto.stackexchange.com/a/57727
    ///
    public func ecdh(with publicKey: K1.PublicKey) throws -> Data {
        try _ecdh(publicKey: publicKey, serializeOutputFunction: .libsecp256kDefault)
    }
    
    /// Computes a shared secret with the provided public key from another party,
    /// returning an uncompressed public point, unhashed.
    ///
    /// This is one of three ECDH functions, this library vendors, all three versions
    /// uses different serialization of the shared EC Point, specifically:
    /// 1. SHA-256 hash the compressed point
    /// 2. No hash, return point uncompressed <- this function
    /// 3. No hash, return only the `X` coordinate of the point.
    ///
    /// This function uses 2. i.e. no hash, return point uncompressed
    /// **This is not following any standard at all**, but might be useful if you want to write your
    /// cryptographic functions, e.g. some ECIES scheme.
    ///
    public func ecdhPoint(with publicKey: K1.PublicKey) throws -> Data {
        try _ecdh(publicKey: publicKey, serializeOutputFunction: .noHashWholePoint)
    }
}

// MUST match https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Agreement/DH.swift#L34

/// A Key Agreement Result
/// A SharedSecret has to go through a Key Derivation Function before being able to use by a symmetric key operation.
public struct __SharedSecret {
    var ss: SecureBytes
}
