//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//


// Bridge to C
import secp256k1
import CryptoKit
import Foundation

// MARK: - Validate (Verify)
// MARK: -
internal extension K1.PublicKey {
    
    func isValidSchnorrSignature<D: DataProtocol>(
        _ signature: SchnorrSignature,
        hashed messageData: D
    ) throws -> Bool {
        let message = [UInt8](messageData)
        guard message.count == K1.Curve.Field.byteCount else {
            throw K1.Error.incorrectByteCountOfMessageToValidate
        }
        return try Bridge.toC { bridge -> Bool in
            let schnorrBytes = [UInt8](signature.rawRepresentation)
            
            var publicKeyBridgedToC = secp256k1_pubkey()

            try bridge.call(ifFailThrow: .failedToParsePublicKeyFromBytes) { context in
                /* Parse a variable-length public key into the pubkey object. */
                secp256k1_ec_pubkey_parse(
                    context,
                    &publicKeyBridgedToC,
                    uncompressedRaw,
                    uncompressedRaw.count
                )
            }

            var publicKeyX = secp256k1_xonly_pubkey()

            try bridge.call(ifFailThrow: .failedToSchnorrVerifyGettingXFromPubKey) { context in
                secp256k1_xonly_pubkey_from_pubkey(context, &publicKeyX, nil, &publicKeyBridgedToC)
            }
    
            return bridge.validate { context in
                secp256k1_schnorrsig_verify(
                    context,
                    schnorrBytes,
                    message,
                    message.count,
                    &publicKeyX
                )
            }
        }
    }
    
    func isValidECDSASignature<D: DataProtocol>(
        _ signature: ECDSASignature,
        hashed messageData: D,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        let message = [UInt8](messageData)
        guard message.count == K1.Curve.Field.byteCount else {
            throw K1.Error.incorrectByteCountOfMessageToValidate
        }
        
        return try Bridge.toC { bridge -> Bool in
            
            var publicKeyBridgedToC = secp256k1_pubkey()

            try bridge.call(ifFailThrow: .failedToParsePublicKeyFromBytes) { context in
                /* Parse a variable-length public key into the pubkey object. */
                secp256k1_ec_pubkey_parse(
                    context,
                    &publicKeyBridgedToC,
                    uncompressedRaw,
                    uncompressedRaw.count
                )
            }
            
            var signatureBridgedToCPotentiallyMalleable = secp256k1_ecdsa_signature()
            withUnsafeMutableBytes(of: &signatureBridgedToCPotentiallyMalleable.data) { pointer in
                pointer.copyBytes(
                    from: signature.rawRepresentation.prefix(pointer.count)
                )
            }
            
            var signatureBridgedToCNonMalleable = secp256k1_ecdsa_signature()

            let codeForSignatureWasMalleable = 1
            let signatureWasMalleableResult = bridge.callWithResultCode { context in
                secp256k1_ecdsa_signature_normalize(
                   context,
                   &signatureBridgedToCNonMalleable, // out
                   &signatureBridgedToCPotentiallyMalleable // in
               )
           }
           
            let signatureWasMalleable = signatureWasMalleableResult == codeForSignatureWasMalleable
     
            let isSignatureValid = bridge.validate { context in
                secp256k1_ecdsa_verify(
                    context,
                    &signatureBridgedToCNonMalleable,
                    message,
                    &publicKeyBridgedToC
                )
            }
            
            let acceptMalleableSignatures = mode == .acceptSignatureMalleability
            
            switch (isSignatureValid, signatureWasMalleable, acceptMalleableSignatures) {
            case (true, false, _):
                // Signature is valid
                return true
            case (true, true, true):
                // Signature was valid but malleable, since you specified to
                // accept malleability => considering signature valid.
                return true
            case (true, true, false):
                // Signature was valid, but not normalized which was required =>
                // considering signature invalid.
                return false
            case (false, _, _):
                // Signature is invalid.
                return false
            }
        }
    }
}

//public enum Schnorr: SignatureScheme {}

// MARK: - Validate ECDSA (Verify)
// MARK: -
public extension K1.PublicKey {
    
    func isValidECDSASignature<D: Digest>(
        _ signature: ECDSASignatureNonRecoverable,
        digest: D,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try isValidECDSASignature(signature, hashed: Data(digest), mode: mode)
    }
    
    func isValid<D: Digest>(signature: ECSignatureBase, for digest: D) throws -> Bool {
        if let schnorrSignature = signature as? SchnorrSignature {
            return try isValidSchnorrSignature(schnorrSignature, digest: digest)
        } else if let ecdsaSignatureRecoverable = signature as? ECDSASignatureRecoverable {
            return try isValidECDSASignature(ecdsaSignatureRecoverable.nonRecoverable(), digest: digest)
        } else if let ecdsaSignatureNonRecoverable = signature as? ECDSASignatureNonRecoverable {
            return try isValidECDSASignature(ecdsaSignatureNonRecoverable, digest: digest)
        } else {
            throw K1.Error.failedToRecognizeSignatureType(onlySupportedSchemesAre: SigningScheme.allCases)
        }
    }
    
    func isValid<D: DataProtocol>(signature: ECSignatureBase, hashed: D) throws -> Bool {
        if let schnorrSignature = signature as? SchnorrSignature {
            return try isValidSchnorrSignature(schnorrSignature, hashed: hashed)
        } else if let ecdsaSignatureRecoverable = signature as? ECDSASignatureRecoverable {
            return try isValidECDSASignature(ecdsaSignatureRecoverable.nonRecoverable(), hashed: hashed)
        } else if let ecdsaSignatureNonRecoverable = signature as? ECDSASignatureNonRecoverable {
            return try isValidECDSASignature(ecdsaSignatureNonRecoverable, hashed: hashed)
        } else {
            throw K1.Error.failedToRecognizeSignatureType(onlySupportedSchemesAre: SigningScheme.allCases)
        }
    }
    
    func isValid<M: DataProtocol>(signature: ECSignatureBase, unhashed: M) throws -> Bool {
       try isValid(signature: signature, for: SHA256.hash(data: unhashed))
    }
    
    func isValidECDSASignature<M: DataProtocol>(
        _ signature: ECDSASignatureNonRecoverable,
        unhashed: M,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try isValidECDSASignature(signature, digest: SHA256.hash(data: unhashed), mode: mode)
    }
    
    func isValidECDSASignature<M: DataProtocol>(
        _ signature: ECDSASignatureRecoverable,
        unhashed: M,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try isValidECDSASignature(signature.nonRecoverable(), unhashed: unhashed, mode: mode)
    }
}

// MARK: - Validate Schnorr (Verify)
// MARK: -
public extension K1.PublicKey {
    
    func isValidSchnorrSignature<D: Digest>(
        _ signature: SchnorrSignature,
        digest: D
    ) throws -> Bool {
        try isValidSchnorrSignature(signature, hashed: Data(digest))
    }
    
    func isValidSchnorrSignature<M: DataProtocol>(
        _ signature: SchnorrSignature,
        unhashed: M
    ) throws -> Bool {
        try isValidSchnorrSignature(signature, digest: SHA256.hash(data: unhashed))
    }
}

/// Validation mode controls whether or not signature malleability should
/// is forbidden or allowed. Read more about it [here][more]
///
/// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
public enum SignatureValidationMode {
    case preventSignatureMalleability
    case acceptSignatureMalleability
}

public extension SignatureValidationMode {
    static let `default`: Self = .acceptSignatureMalleability
}

public protocol ECSignatureBase {
    static var scheme: SigningScheme { get }
    
    func wasSigned<D: Digest>(
        by signer: K1.PublicKey,
        for digest: D
    ) throws -> Bool
}

public protocol ECSignature: ECSignatureBase {
    associatedtype Scheme: ECSignatureScheme
    associatedtype ValidationMode
    associatedtype SigningMode
    
    func wasSigned<D: Digest>(
        by signer: K1.PublicKey,
        for digest: D,
        mode: ValidationMode
    ) throws -> Bool
    
    func wasSigned<D: DataProtocol>(
        by signer: K1.PublicKey,
        hashedMessage: D,
        mode: ValidationMode
    ) throws -> Bool
    
    static func by<D: DataProtocol>(
        signing hashed: D,
        with privateKey: K1.PrivateKey,
        mode: SigningMode
    ) throws -> Self
}

public extension ECSignature where ValidationMode == Void {
    
    func wasSigned<D: Digest>(
        by signer: K1.PublicKey,
        for digest: D
    ) throws -> Bool {
        try wasSigned(by: signer, for: digest, mode: ())
    }
}

public extension ECSignature {
      
    static func bySigning<D: Digest>(
        digest: D,
        with privateKey: K1.PrivateKey,
        mode: SigningMode
    ) throws -> Self {
        try by(signing: Array(digest), with: privateKey, mode: mode)
    }
    
    static func bySigning<D: DataProtocol>(
        unhashed data: D,
        with privateKey: K1.PrivateKey,
        mode: SigningMode
    ) throws -> Self {
        try bySigning(digest: SHA256.hash(data: data), with: privateKey, mode: mode)
    }
}

public extension ECDSASignature {
    
    typealias ValidationMode = SignatureValidationMode

    struct SigningMode {
        public let nonceFunctionArbitraryData: Data?
        public init(nonceFunctionArbitraryData: Data? = nil) {
            self.nonceFunctionArbitraryData = nonceFunctionArbitraryData
        }
    }
    
    static func by<D: DataProtocol>(
        signing hashed: D,
        with privateKey: K1.PrivateKey,
        mode: SigningMode
    ) throws -> Self {
        try privateKey.ecdsaSignNonRecoverable(hashed: hashed, mode: mode)
    }
    
    func wasSigned<D: DataProtocol>(
        by signer: K1.PublicKey,
        hashedMessage: D,
        mode: ValidationMode = .default
    ) throws -> Bool {
        try signer.isValidECDSASignature(self, hashed: hashedMessage, mode: mode)
    }
    
    func wasSigned<D: Digest>(by signer: K1.PublicKey, for digest: D) throws -> Bool {
        try wasSigned(by: signer, for: digest, mode: .default)
    }
    
    func wasSigned<D: Digest>(
        by signer: K1.PublicKey,
        for digest: D,
        mode: ValidationMode = .default
    ) throws -> Bool {
        try signer.isValidECDSASignature(
            self,
            digest: digest,
            mode: mode
        )
    }
}

public extension ECDSASignature.SigningMode {
    static let `default`: Self = .init()
}

public protocol ECSignatureScheme where Signature.Scheme == Self {
    associatedtype Hasher: HashFunction
    associatedtype Signature: ECSignature
    static var scheme: SigningScheme { get }
}
public extension ECSignatureScheme {
    typealias HashDigest = Hasher.Digest
    static func hash<D: DataProtocol>(unhashed: D) throws -> HashDigest {
        Hasher.hash(data: unhashed)
    }
}


public extension ECSignatureScheme {
    static var scheme: SigningScheme { Signature.scheme }
}

public enum ECDSA: ECSignatureScheme {
    public typealias Hasher = SHA256
    public typealias Signature = ECDSASignature
}

public enum Schnorr: ECSignatureScheme {
    public typealias Hasher = SHA256
    public typealias Signature = SchnorrSignature
}

public enum SigningScheme: String, Equatable, CaseIterable {
    case schnorr
    case ecdsa
}

public struct SchnorrSignature: ECSignature, Sendable, Hashable {
    public typealias Scheme = Schnorr
    private let _rawRepresentation: [UInt8]
    public var rawRepresentation: Data {
        Data(_rawRepresentation)
    }
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
        guard
            rawRepresentation.count == 2 * K1.Curve.Field.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self._rawRepresentation = [UInt8](rawRepresentation)
    }
}

public extension SchnorrSignature {
    static let scheme: SigningScheme = .schnorr
    typealias ValidationMode = Void
    
    func compactRepresentation() throws -> Data {
        try Bridge.compactRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
    func derRepresentation() throws -> Data {
        try Bridge.derRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
    
    func wasSigned<D: Digest>(
        by signer: K1.PublicKey,
        for digest: D,
        mode _: Void
    ) throws -> Bool {
        try signer.isValidSchnorrSignature(self, digest: digest)
    }
    
    
    func wasSigned<D: DataProtocol>(
        by signer: K1.PublicKey,
        hashedMessage: D,
        mode: ValidationMode
    ) throws -> Bool {
        try signer.isValidSchnorrSignature(self, hashed: hashedMessage)
    }
    
    typealias SigningMode = SchnorrInput
    
    static func by<D: DataProtocol>(
        signing hashed: D,
        with privateKey: K1.PrivateKey,
        mode: SigningMode
    ) throws -> Self {
        try privateKey.schnorrSign(hashed: hashed, input: mode)
    }
    
}
