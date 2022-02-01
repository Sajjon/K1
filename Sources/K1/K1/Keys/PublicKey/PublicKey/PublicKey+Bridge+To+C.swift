//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//

import Foundation

// Bridge to C
import secp256k1
import Crypto

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

            try bridge.call(ifFailThrow: .failedToSerializePublicKeyIntoBytes) { context in
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

            try bridge.call(ifFailThrow: .failedToSerializePublicKeyIntoBytes) { context in
                /* "Serialize a pubkey object into a serialized byte sequence." */
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
        _ signature: ECDSASignature,
        digest: D,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try isValidECDSASignature(signature, hashed: Data(digest), mode: mode)
    }
    
    func isValidECDSASignature<M: DataProtocol>(
        _ signature: ECDSASignature,
        unhashed: M,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        try isValidECDSASignature(signature, digest: SHA256.hash(data: unhashed), mode: mode)
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

public protocol ECSignature {
    associatedtype ValidationMode
    func compactRepresentation() throws -> Data
    func derRepresentation() throws -> Data
    func by<D: Digest>(
        _ signer: K1.PublicKey,
        of digest: D,
        mode: ValidationMode
    ) throws -> Bool
}

public extension ECSignature where ValidationMode == Void {
    
    func by<D: Digest>(
        _ signer: K1.PublicKey,
        of digest: D
    ) throws -> Bool {
        try by(signer, of: digest, mode: ())
    }
}

extension ECDSASignature: ECSignature {}

public extension ECDSASignature {
    
    typealias ValidationMode = SignatureValidationMode
    
    func by<D: Digest>(
        _ signer: K1.PublicKey,
        of digest: D,
        mode: SignatureValidationMode = .default
    ) throws -> Bool {
        
        try signer.isValidECDSASignature(
            self,
            digest: digest,
            mode: mode
        )
    }
}

public protocol SignatureScheme {
    associatedtype Signature: ECSignature
}

public enum ECDSA: SignatureScheme {
    public typealias Signature = ECDSASignature
}


public struct SchnorrSignature: ECSignature, Equatable {
    
    internal let rawRepresentation: Data
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
        guard
            rawRepresentation.count == 2 * K1.Curve.Field.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self.rawRepresentation = Data(rawRepresentation)
    }
}
public extension SchnorrSignature {
    typealias ValidationMode = Void
    
    func compactRepresentation() throws -> Data {
        try Bridge.compactRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
    func derRepresentation() throws -> Data {
        try Bridge.derRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
    
    func by<D: Digest>(
        _ signer: K1.PublicKey,
        of digest: D,
        mode _: Void
    ) throws -> Bool {
        try signer.isValidSchnorrSignature(self, digest: digest)
    }
}
