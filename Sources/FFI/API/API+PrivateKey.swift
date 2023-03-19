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
        }
    }
}

// MARK: Init
extension Bridge.PrivateKey.Wrapped {
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
                    let _ = try Bridge.PrivateKey.Wrapped(secureBytes: secureBytes)
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

extension Bridge.PrivateKey {
    public static func from(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(bytes: [UInt8](rawRepresentation))
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

// MARK: ECDSA Shared
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
}
    
// MARK: ECDSA Recoverable
extension Bridge.PrivateKey {
    
    /// Produces a **recoverable** ECDSA signature from a hashed `message`
    public static func ecdsaSignRecoverable(
        hashedMessage: [UInt8],
        privateKey: Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> Bridge.ECDSA.Recovery.Wrapped {
        try Self.ecdsa(message: hashedMessage, privateKey: privateKey, mode: mode)
    }
}

// MARK: ECDSA Non-Recoverable
extension Bridge.PrivateKey {
    /// Produces a **non recoverable** ECDSA signature from a hashed `message`
    public static func ecdsaSignNonRecoverable(
        hashedMessage: [UInt8],
        privateKey: Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> Bridge.ECDSA.NonRecovery.Wrapped {
        try Self.ecdsa(message: hashedMessage, privateKey: privateKey, mode: mode)
    }
}
