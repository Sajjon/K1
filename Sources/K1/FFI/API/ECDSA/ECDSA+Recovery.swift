import Foundation
import secp256k1

extension FFI.ECDSA.Recovery {
    static let byteCount = FFI.ECDSA.NonRecovery.byteCount + 1
    final class Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
        
        static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
            secp256k1_ecdsa_sign_recoverable
        }
        
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
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
    
    static func from(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(raw: Raw.recoverableSignature(rawRepresentation))
    }
    
    static func recover(
        _ wrapped: Wrapped,
        message: [UInt8]
    ) throws -> FFI.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var raw = secp256k1_pubkey()
        try FFI.call(
            ifFailThrow: .failedToRecoverPublicKey
        ) { context in
            secp256k1_ecdsa_recover(context, &raw, &wrapped.raw, message)
        }
        return FFI.PublicKey.Wrapped(raw: raw)
    }
    
    static func deserializeCompact(
        rs: [UInt8],
        recoveryID recid: Int32
    ) throws -> Wrapped {
        var raw = Wrapped.Raw()
        try FFI.call(
            ifFailThrow: .failedSignatureToConvertRecoverableSignatureToCompact
        ) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &raw,
                rs,
                recid
            )
        }
        return .init(raw: raw)
    }
    
    static func serializeCompact(
        _ wrapped: Wrapped
    ) throws -> (rs: [UInt8], recoveryID: Int32) {
        var rs = [UInt8](repeating: 0, count: FFI.ECDSA.NonRecovery.byteCount)
        var recoveryID: Int32 = 0
        
        try FFI.call(
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
    
    static func nonRecoverable(
        _ wrapped: Wrapped
    ) throws -> FFI.ECDSA.NonRecovery.Wrapped {
        
        
        var raw = secp256k1_ecdsa_signature()
        
        try FFI.call(
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
