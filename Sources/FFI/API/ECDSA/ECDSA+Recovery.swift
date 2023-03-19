import Foundation
import secp256k1

extension Bridge.ECDSA.Recovery {
    public static let byteCount = Bridge.ECDSA.NonRecovery.byteCount + 1
    public final class Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
        
        static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
            secp256k1_ecdsa_sign_recoverable
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try Swift.withUnsafeBytes(of: &raw.data) { pointer in
                try body(pointer)
            }
        }
        
        typealias Raw = secp256k1_ecdsa_recoverable_signature
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
    
    public static func from(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(raw: Raw.recoverableSignature(rawRepresentation))
    }
    
    public static func recover(
        _ wrapped: Wrapped,
        message: [UInt8]
    ) throws -> Bridge.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var raw = secp256k1_pubkey()
        try Bridge.call(
            ifFailThrow: .failedToRecoverPublicKey
        ) { context in
            secp256k1_ecdsa_recover(context, &raw, &wrapped.raw, message)
        }
        return Bridge.PublicKey.Wrapped(raw: raw)
    }
    
    public static func serialize(
        _ wrapped: Wrapped
    ) throws -> (rs: [UInt8], recoveryID: Int32) {
        var rs = [UInt8](repeating: 0, count: Bridge.ECDSA.NonRecovery.byteCount)
        var recoveryID: Int32 = 0
        
        try Bridge.call(
            ifFailThrow: .failedSignatureToConvertRecoverableSignatureToCompact
        ) { context in
            secp256k1_ecdsa_recoverable_signature_serialize_compact(
                context,
                &rs,
                &recoveryID,
                &wrapped.raw
            )
        }
        return (rs, recoveryID)
    }
    
    public static func nonRecoverable(
        _ wrapped: Wrapped
    ) throws -> Bridge.ECDSA.NonRecovery.Wrapped {
        
        
        var raw = secp256k1_ecdsa_signature()
        
        try Bridge.call(
            ifFailThrow: .failedToConvertRecoverableSignatureToNonRecoverable
        ) { context in
            secp256k1_ecdsa_recoverable_signature_convert(
                context,
                &raw,
                &wrapped.raw
            )
        }
        
        return .init(raw: raw)
    }
}
