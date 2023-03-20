//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension Bridge {
    public enum ECDSA {}
}
extension Bridge.ECDSA {
    
    /// Whether or not to consider malleable signatures valid.
    ///
    /// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
    public enum ValidationMode {
        /// Considers all malleable signatures **invalid**.
        case preventSignatureMalleability
        /// Accepts malleable signatures valid.
        case acceptSignatureMalleability
    }
    
    public struct SigningMode {
        public let nonceFunctionArbitraryData: Data?
        public init(nonceFunctionArbitraryData: Data? = nil) {
            self.nonceFunctionArbitraryData = nonceFunctionArbitraryData
        }
        public static let `default` = Self()
    }
    
    
    public enum Recovery {}
    public enum NonRecovery {}
}

extension Bridge.ECDSA.ValidationMode {
    public static let `default`: Self = .acceptSignatureMalleability
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
extension Bridge.ECDSA {
    
    private static func _sign<WrappedSignature>(
        message: [UInt8],
        privateKey: Bridge.PrivateKey.Wrapped,
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
extension Bridge.ECDSA.Recovery {
    
    /// Produces a **recoverable** ECDSA signature from a hashed `message`
    public static func sign(
        hashedMessage: [UInt8],
        privateKey: Bridge.PrivateKey.Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> Bridge.ECDSA.Recovery.Wrapped {
       
        try Bridge.ECDSA._sign(
            message: hashedMessage,
            privateKey: privateKey,
            mode: mode
        )
    }
}

// MARK: ECDSA Non-Recoverable
extension Bridge.ECDSA.NonRecovery {
    
    /// Produces a **non recoverable** ECDSA signature from a hashed `message`
    public static func sign(
        hashedMessage: [UInt8],
        privateKey: Bridge.PrivateKey.Wrapped,
        mode: Bridge.ECDSA.SigningMode
    ) throws -> Bridge.ECDSA.NonRecovery.Wrapped {
        
        try Bridge.ECDSA._sign(
            message: hashedMessage,
            privateKey: privateKey,
            mode: mode
        )
    }
}
