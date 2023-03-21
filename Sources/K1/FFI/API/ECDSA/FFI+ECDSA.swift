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
    public struct ValidationInput {
        /// Whether or not to consider malleable signatures valid.
        ///
        /// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
        public enum MalleabilityStrictness {
            /// Considers all malleable signatures **invalid**.
            case rejected
            
            /// Accepts malleable signatures valid.
            case accepted
        }
        public let malleabilityStrictness: MalleabilityStrictness
        public init(malleabilityStrictness: MalleabilityStrictness) {
            self.malleabilityStrictness = malleabilityStrictness
        }
        public static let `default`: Self = .init(
            malleabilityStrictness: .rejected
        )
    }
    
    public struct SigningInput: Sendable, Hashable {
        public let nonceFunction: NonceFunction
        public enum NonceFunction: Sendable, Hashable {
            case random
            
            /// RFC6979
            case deterministic(arbitraryData: RFC6979ArbitraryData? = nil)
            public struct RFC6979ArbitraryData: Sendable, Hashable {
                public let arbitraryData: [UInt8]
                public init(arbitraryData: [UInt8]) throws {
                    guard arbitraryData.count == Curve.Field.byteCount else {
                        throw K1.Error.incorrectByteCountOfArbitraryDataForNonceFunction
                    }
                    self.arbitraryData = arbitraryData
                }
            }
        }
        public init(nonceFunction: NonceFunction) {
            self.nonceFunction = nonceFunction
        }
        public static let `default`: Self = .init(nonceFunction: .deterministic())
    }
}


extension FFI {
    public enum ECDSA {}
}
extension FFI.ECDSA {
    public enum Recovery {}
    public enum NonRecovery {}
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
        input: K1.ECDSA.SigningInput = .default
    ) throws -> WrappedSignature where WrappedSignature: WrappedECDSASignature {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToSignMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
    
        var raw = WrappedSignature.Raw()
        
        try FFI.call(
            ifFailThrow: .failedToECDSASignDigest
        ) { context in
            WrappedSignature.sign()(
                context,
                &raw,
                message,
                privateKey.secureBytes.backing.bytes,
                input.nonceFunction.function(),
                input.arbitraryData
            )
        }
        
        return .init(raw: raw)
        
    }
}
extension K1.ECDSA.SigningInput {
    fileprivate var arbitraryData: [UInt8]? {
        switch self.nonceFunction {
        case .random: return nil
        case let .deterministic(arbitraryData): return arbitraryData?.arbitraryData
        }
    }
    
}
extension K1.ECDSA.SigningInput.NonceFunction {
    fileprivate func function() -> Optional<@convention(c) (Optional<UnsafeMutablePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafeMutableRawPointer>, UInt32) -> Int32> {
        switch self {
        case .deterministic: return secp256k1_nonce_function_rfc6979
        case .random: return secureRandomNonce
        }
    }
}
    

/** A pointer to a function to deterministically generate a nonce.
 *
 * Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
 * Out:     nonce32:   pointer to a 32-byte array to be filled by the function.
 * In:      msg32:     the 32-byte message hash being verified (will not be NULL)
 *          key32:     pointer to a 32-byte secret key (will not be NULL)
 *          algo16:    pointer to a 16-byte array describing the signature
 *                     algorithm (will be NULL for ECDSA for compatibility).
 *          data:      Arbitrary data pointer that is passed through.
 *          attempt:   how many iterations we have tried to find a nonce.
 *                     This will almost always be 0, but different attempt values
 *                     are required to result in a different nonce.
 *
 * Except for test cases, this function should compute some cryptographic hash of
 * the message, the algorithm, the key and the attempt.
 */
var secureRandomNonce: (@convention(c)(
    _ out: UnsafeMutablePointer<UInt8>?,
    _ msg: UnsafePointer<UInt8>?,
    _ key32: UnsafePointer<UInt8>?,
    _ algo16: UnsafePointer<UInt8>?,
    _ data: UnsafeMutableRawPointer?,
    _ attempt: UInt32
) -> Int32)? {
    return { target, msg, key, algo, data, attempt in
     
        let secureBytes = SecureBytes(count: 32)
        secureBytes.withUnsafeBytes { sourceBytes in
            target?.assign(from: sourceBytes.baseAddress!
                .assumingMemoryBound(to: UInt8.self), count: 32)
        }
        return Int32(1)
    }
}
