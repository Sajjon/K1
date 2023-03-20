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
        case .random: fatalError()
        }
    }
}
    

