//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension K1 {
    public enum ECDSA {}
}
extension K1.ECDSA {
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
}


extension FFI {
    public enum ECDSA {}
}
extension FFI.ECDSA {
    public enum Recovery {}
    public enum NonRecovery {}
}

extension K1.ECDSA.ValidationMode {
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
extension FFI.ECDSA {
    
    internal static func _sign<WrappedSignature>(
        message: [UInt8],
        privateKey: FFI.PrivateKey.Wrapped,
        mode: K1.ECDSA.SigningMode
    ) throws -> WrappedSignature where WrappedSignature: WrappedECDSASignature {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        
        
        var nonceFunctionArbitraryBytes: [UInt8]? = nil
        if let nonceFunctionArbitraryData = mode.nonceFunctionArbitraryData {
            guard nonceFunctionArbitraryData.count == Curve.Field.byteCount else {
                throw K1.Error.incorrectByteCountOfArbitraryDataForNonceFunction
            }
            nonceFunctionArbitraryBytes = [UInt8](nonceFunctionArbitraryData)
        }
        
        var raw = WrappedSignature.Raw()
        
        try FFI.call(
            ifFailThrow: .failedToECDSASignDigest
        ) { context in
            WrappedSignature.sign()(context, &raw, message, privateKey.secureBytes.backing.bytes, secp256k1_nonce_function_rfc6979, nonceFunctionArbitraryBytes)
        }
        
        return .init(raw: raw)
        
    }
}
    

