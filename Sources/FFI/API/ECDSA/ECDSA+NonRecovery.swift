import Foundation
import secp256k1


extension Bridge.ECDSA.NonRecovery {
    
    
    public static let byteCount = 2 * Curve.Field.byteCount
    
    public final class Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
        
        static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
            secp256k1_ecdsa_sign
        }
        
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try Swift.withUnsafeBytes(of: &raw.data) { pointer in
                try body(pointer)
            }
        }
        
        typealias Raw = secp256k1_ecdsa_signature
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
    
    public static func from(
        compactBytes: [UInt8]
    ) throws -> Wrapped {
        try Wrapped(
            raw: Raw.nonRecoverableSignature(compactBytes: compactBytes)
        )
    }
    
    public static func from(
        derRepresentation: [UInt8]
    ) throws -> Wrapped {
        try Wrapped(
            raw: Raw.nonRecoverableSignature(derBytes: derRepresentation)
        )
    }
    
    public static func compact(_ wrapped: Wrapped) throws -> Data {
        
        var out = [UInt8](repeating: 0, count: Self.byteCount)
        
        try Bridge.call(ifFailThrow: .failedToSerializeSignature) { context in
            secp256k1_ecdsa_signature_serialize_compact(context, &out, &wrapped.raw)
        }
        return Data(out)
    }
    
    public static func recoverPublicKey(
        _ wrapped: Wrapped,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> Bridge.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        let nonRecoverableCompact = try Bridge.ECDSA.NonRecovery.compact(wrapped)
        return try Self.recoverPublicKey(
            nonRecoverableCompact: nonRecoverableCompact,
            recoveryID: recoveryID,
            message: message
        )
    }
    
    public static func recoverPublicKey(
        nonRecoverableCompact: Data,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> Bridge.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var compact = [UInt8](nonRecoverableCompact)
        var recoverable = secp256k1_ecdsa_recoverable_signature()
        try Bridge.call(ifFailThrow: .failedToParseRecoverableSignatireFromCompact) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &recoverable,
                &compact,
                recoveryID
            )
        }
        var publicKeyRaw = secp256k1_pubkey()
        try Bridge.call(ifFailThrow: .failedToRecoverPublicKey) { context in
            secp256k1_ecdsa_recover(
                context,
                &publicKeyRaw,
                &recoverable,
                message
            )
        }
        return Bridge.PublicKey.Wrapped(raw: publicKeyRaw)
    }
    
    public static func der(
        _ wrapped: Wrapped
    ) throws -> Data {
        var derMaxLength = 75 // in fact max is 73, but we can have some margin.
        var derSignature = [UInt8](repeating: 0, count: derMaxLength)
        
        try Bridge.call(ifFailThrow: .failedToSerializeDERSignature) { context in
            secp256k1_ecdsa_signature_serialize_der(
                context,
                &derSignature,
                &derMaxLength,
                &wrapped.raw
            )
        }
        return Data(derSignature.prefix(derMaxLength))
    }
    
}


