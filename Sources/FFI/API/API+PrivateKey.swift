//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-18.
//

import Foundation
import secp256k1

extension Bridge {
    public enum PrivateKey {
        public final class Wrapped: @unchecked Sendable {
            
            public let publicKey: Bridge.PublicKey.Wrapped
            internal let secureBytes: SecureBytes
            
            fileprivate init(secureBytes: SecureBytes) throws {
                guard secureBytes.count == Curve.Field.byteCount else {
                    throw Error.failedToInitializePrivateKeyIncorrectByteCount(
                        got: secureBytes.count,
                        expected: Curve.Field.byteCount
                    )
                }
                if secureBytes.allSatisfy({ $0 == .zero }) {
                    throw Bridge.Error.invalidPrivateKeyMustNotBeZero
                }
                
                self.secureBytes = secureBytes
                var secureBytes = secureBytes
                self.publicKey = try secureBytes.withUnsafeMutableBytes { seckey in
                    var raw = secp256k1_pubkey()
                    
                    try Bridge.call(ifFailThrow: .invalidPrivateKeyMustBeSmallerThanOrder) { context in
                        secp256k1_ec_pubkey_create(context, &raw, seckey.baseAddress!)
                    }
                    
                    return Bridge.PublicKey.Wrapped(raw: raw)
                }
            }
            
            fileprivate convenience init(bytes: [UInt8]) throws {
                try self.init(secureBytes: .init(bytes: bytes))
            }
            
            public convenience init() {
                func generateNew() -> SecureBytes {
                    var attempt = 0
                    
                    while attempt < 100 {
                        defer { attempt += 1 }
                        do {
                            let secureBytes = SecureBytes(count: Curve.Field.byteCount)
                            let _ = try Wrapped(secureBytes: secureBytes)
                            return secureBytes
                        } catch {
                            // Failure (due to unlikely scenario that the private key scalar > order of the curve) => retry
                        }
                    }
                    
                    // Probability of this happening is:
                    // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
                    // (n / 2^256) ^ 100 = lim 0
                    // I.e. will not happen.
                    fatalError("""
                                Failed to generate private key after #\(attempt) attempts.
                                You are the most unlucky person in the universe.
                                Or by Occam's razor: the person writing this code made some error.
                                """
                    )
                }
                try! self.init(secureBytes: generateNew())
            }
            
        }
        
        
        public static func from(
            rawRepresentation: some DataProtocol
        ) throws -> Wrapped {
            try Wrapped(bytes: [UInt8](rawRepresentation))
        }
    }
}

protocol RawECDSASignature {
    init()
}
extension secp256k1_ecdsa_recoverable_signature: RawECDSASignature {}
extension secp256k1_ecdsa_signature: RawECDSASignature {}

protocol WrappedECDSASignature {
    associatedtype Raw: RawECDSASignature
    init(raw: Raw)
    var raw: Raw { get }
    static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32
}

extension Bridge.PrivateKey {
    
    private static func ecdsa<WrappedSignature>(
        message: [UInt8],
        privateKey: Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> WrappedSignature where WrappedSignature: WrappedECDSASignature {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        
        
        var nonceFunctionArbitraryBytes: [UInt8]? = nil
        if let nonceFunctionArbitraryData = mode.nonceFunctionArbitraryData {
            guard nonceFunctionArbitraryData.count == Curve.Field.byteCount else {
                throw Bridge.Error.incorrectByteCountOfArbitraryDataForNonceFunction
            }
            nonceFunctionArbitraryBytes = [UInt8](nonceFunctionArbitraryData)
        }
        
        var raw = WrappedSignature.Raw()
        
        try Bridge.call(
            ifFailThrow: .failedToECDSASignDigest
        ) { context in
            WrappedSignature.sign()(context, &raw, message, privateKey.secureBytes.backing.bytes, secp256k1_nonce_function_rfc6979, nonceFunctionArbitraryBytes)
        }
        
        return .init(raw: raw)
        
    }
    
    
    /// Produces a **recoverable** ECDSA signature from a hashed `message`
    public static func ecdsaSignRecoverable(
        hashedMessage: [UInt8],
        privateKey: Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> Bridge.ECDSA.Recovery.Wrapped {
        try Self.ecdsa(message: hashedMessage, privateKey: privateKey, mode: mode)
    }
    
    /// Produces a **non recoverable** ECDSA signature from a hashed `message`
    public static func ecdsaSignNonRecoverable(
        hashedMessage: [UInt8],
        privateKey: Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> Bridge.ECDSA.NonRecovery.Wrapped {
        try Self.ecdsa(message: hashedMessage, privateKey: privateKey, mode: mode)
    }
    
    public static func schnorrSign(
        hashedMessage message: [UInt8],
        privateKey: Wrapped,
        input: SchnorrInput?
    ) throws -> Bridge.Scnhorr.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var signatureOut = [UInt8](repeating: 0, count: Bridge.Scnhorr.Wrapped.byteCount)
        
        var keyPair = secp256k1_keypair()
        
        try Bridge.call(
            ifFailThrow: .failedToInitializeKeyPairForSchnorrSigning
        ) { context in
            secp256k1_keypair_create(context, &keyPair, privateKey.secureBytes.backing.bytes)
        }
        
        var auxilaryRandomBytes: [UInt8]? = nil
        if let auxilaryRandomData = input?.auxilaryRandomData {
            guard auxilaryRandomData.count == Curve.Field.byteCount else {
                throw Bridge.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
            }
            auxilaryRandomBytes = [UInt8](auxilaryRandomData)
        }
        
        try Bridge.call(
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
        
        return try Bridge.Scnhorr.Wrapped(bytes: signatureOut)
    }

}


public struct SchnorrInput {
    public let auxilaryRandomData: Data
    public init(auxilaryRandomData: Data) {
        self.auxilaryRandomData = auxilaryRandomData
    }
}


extension Bridge {
    public enum ECDH  {}
}


extension Bridge.ECDH {
    
    
    public enum SerializeFunction {
        
        /// Using the `libsecp256k1` default behaviour.
        ///
        /// SHA256 hashes the **compressed** shared point.
        /// Accepts arbitrary data passed through hash function as well.
        ///
        case libsecp256kDefault(arbitraryData: Data?)
        
        /// Following the [ANSI X9.63][ansix963] standard
        ///
        /// No hash, returns `X` component of shared point only.
        ///
        /// [ansix963]:  https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
        case ansiX963
        
        /// Following no standard at all.
        ///
        /// No hash, returns the whole shared point.
        ///
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
            case .libsecp256kDefault: return Curve.Field.byteCount
            case .ansiX963: return Curve.Field.byteCount
            case .noHashWholePoint: return Bridge.Format.uncompressed.length
            }
        }
    }
    
    public static func keyExchange(
        publicKey: Bridge.PublicKey.Wrapped,
        privateKey: Bridge.PrivateKey.Wrapped,
        serializeOutputFunction hashFp: SerializeFunction
    ) throws -> Data {
        
        var sharedPublicPointBytes = [UInt8](
            repeating: 0,
            count: hashFp.outputByteCount
        )
        var arbitraryData: [UInt8]? = {
            switch hashFp {
            case let .libsecp256kDefault(arbitraryData?): return [UInt8](arbitraryData)
            case .libsecp256kDefault(.none): return nil
            case .ansiX963, .noHashWholePoint: return nil
            }
        }()
        try Bridge.call(
            ifFailThrow: .failedToPerformDiffieHellmanKeyExchange
        ) { context in
            secp256k1_ecdh(
                context,
                &sharedPublicPointBytes, // output
                &publicKey.raw, // pubkey
                privateKey.secureBytes.backing.bytes, // seckey
                hashFp.hashfp(), // hashfp
                &arbitraryData // arbitrary data pointer that is passed through to hashfp
            )
        }
        
        return Data(sharedPublicPointBytes)
        
    }
}

