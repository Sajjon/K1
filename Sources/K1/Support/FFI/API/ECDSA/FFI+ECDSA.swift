//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

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
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> WrappedSignature where WrappedSignature: WrappedECDSASignature {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToSignMessageHasInvalidLength(
                got: message.count,
                expected: Curve.Field.byteCount
            )
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
                options.nonceFunction.function(),
                options.arbitraryData
            )
        }
        
        return .init(raw: raw)
        
    }
}
extension K1.ECDSA.SigningOptions {
    fileprivate var arbitraryData: [UInt8]? {
        switch self.nonceFunction {
        case .random: return nil
        case let .deterministic(arbitraryData): return arbitraryData?.arbitraryData
        }
    }
    
}
extension K1.ECDSA.SigningOptions.NonceFunction {
    fileprivate func function() -> Optional<@convention(c) (Optional<UnsafeMutablePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafeMutableRawPointer>, UInt32) -> Int32> {
        switch self {
        case .deterministic:
            return secp256k1_nonce_function_rfc6979
       
        case .random:
            return { (
                nonce32: UnsafeMutablePointer<UInt8>?, // Out: pointer to a 32-byte array to be filled by the function.
                msg: UnsafePointer<UInt8>?, // In: the 32-byte message hash being verified (will not be NULL)
                key32: UnsafePointer<UInt8>?, // In: pointer to a 32-byte secret key (will not be NULL)
                algo16: UnsafePointer<UInt8>?, // In:  pointer to a 16-byte array describing the signature algorithm (will be NULL for ECDSA for compatibility).
                arbitraryData: UnsafeMutableRawPointer?, // In: Arbitrary data pointer that is passed through.
                attemptIndex: UInt32 // In: how many iterations we have tried to find a nonce. This will almost always be 0, but different attempt values are required to result in a different nonce.
            ) -> Int32 /* Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail. */ in
                
                SecureBytes(count: Curve.Field.byteCount).withUnsafeBytes {
                    nonce32?.assign(from: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: $0.count)
                }
                
                // Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
                return 1
            }
        }
    }
}
    
