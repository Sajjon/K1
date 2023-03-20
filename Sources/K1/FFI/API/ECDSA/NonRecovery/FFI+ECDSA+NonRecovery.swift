import Foundation
import secp256k1

// MARK: Deserialize
extension FFI.ECDSA.NonRecovery {
    static let byteCount = 2 * Curve.Field.byteCount
    
    static func from(
        compactBytes: [UInt8]
    ) throws -> Wrapped {
        try Wrapped(
            raw: Raw.nonRecoverableSignature(compactBytes: compactBytes)
        )
    }
    
    static func from(
        derRepresentation: [UInt8]
    ) throws -> Wrapped {
        try Wrapped(
            raw: Raw.nonRecoverableSignature(derBytes: derRepresentation)
        )
    }
}

// MARK: Serialize
extension FFI.ECDSA.NonRecovery {
    static func compact(_ wrapped: Wrapped) throws -> Data {
        var out = [UInt8](repeating: 0, count: Self.byteCount)
        try FFI.call(ifFailThrow: .failedToSerializeSignature) { context in
            secp256k1_ecdsa_signature_serialize_compact(context, &out, &wrapped.raw)
        }
        return Data(out)
    }
    
    static func der(
        _ wrapped: Wrapped
    ) throws -> Data {
        var derMaxLength = 75 // in fact max is 73, but we can have some margin.
        var derSignature = [UInt8](repeating: 0, count: derMaxLength)
        
        try FFI.call(ifFailThrow: .failedToSerializeDERSignature) { context in
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

// MARK: Recover
extension FFI.ECDSA.NonRecovery {
    
    static func recoverPublicKey(
        _ wrapped: Wrapped,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> FFI.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        let nonRecoverableCompact = try FFI.ECDSA.NonRecovery.compact(wrapped)
        return try Self.recoverPublicKey(
            nonRecoverableCompact: nonRecoverableCompact,
            recoveryID: recoveryID,
            message: message
        )
    }
    
    static func recoverPublicKey(
        nonRecoverableCompact: Data,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> FFI.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToRecoverMessageHasInvalidLength(
                got: message.count,
                expected: Curve.Field.byteCount
            )
        }
        var compact = [UInt8](nonRecoverableCompact)
        var recoverable = secp256k1_ecdsa_recoverable_signature()
        try FFI.call(ifFailThrow: .failedToParseRecoverableSignatireFromCompact) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &recoverable,
                &compact,
                recoveryID
            )
        }
        var publicKeyRaw = secp256k1_pubkey()
        try FFI.call(ifFailThrow: .failedToRecoverPublicKey) { context in
            secp256k1_ecdsa_recover(
                context,
                &publicKeyRaw,
                &recoverable,
                message
            )
        }
        return FFI.PublicKey.Wrapped(raw: publicKeyRaw)
    }
}


// MARK: Sign
extension FFI.ECDSA.NonRecovery {
    
    /// Produces a **non recoverable** ECDSA signature from a hashed `message`
    static func sign(
        hashedMessage: [UInt8],
        privateKey: FFI.PrivateKey.Wrapped,
        mode: K1.ECDSA.SigningMode
    ) throws -> FFI.ECDSA.NonRecovery.Wrapped {
        
        try FFI.ECDSA._sign(
            message: hashedMessage,
            privateKey: privateKey,
            mode: mode
        )
    }
}
