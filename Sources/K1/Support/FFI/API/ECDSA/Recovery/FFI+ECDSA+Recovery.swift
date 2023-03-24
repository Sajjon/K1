import Foundation
import secp256k1

// MARK: Deserialize
extension FFI.ECDSA.Recovery {
    static let byteCount = FFI.ECDSA.NonRecovery.byteCount + 1
    
    static func deserialize(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(raw: Raw.recoverableSignature(rawRepresentation))
    }
    
    /// Compact aka `IEEE P1363` aka `R||S`.
    static func deserialize(
        compact rs: [UInt8],
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
}


// MARK: Serialize
extension FFI.ECDSA.Recovery {
    static func serializeCompact(
        _ wrapped: Wrapped
    ) throws -> (rs: [UInt8], recoveryID: Int32) {
        var rs = [UInt8](repeating: 0, count: FFI.ECDSA.NonRecovery.byteCount)
        var recoveryID: Int32 = 0
        var rawSignature = wrapped.raw
        try FFI.call(
            ifFailThrow: .failedSignatureToConvertRecoverableSignatureToCompact
        ) { context in
            secp256k1_ecdsa_recoverable_signature_serialize_compact(
                context,
                &rs,
                &recoveryID,
                &rawSignature
            )
        }
        return (rs, recoveryID)
    }
}

// MARK: Convert
extension FFI.ECDSA.Recovery {
    static func nonRecoverable(
        _ wrapped: Wrapped
    ) throws -> FFI.ECDSA.NonRecovery.Wrapped {
        
        
        var nonRecoverable = secp256k1_ecdsa_signature()
        var recoverable = wrapped.raw
        
        try FFI.call(
            ifFailThrow: .failedToConvertRecoverableSignatureToNonRecoverable
        ) { context in
            secp256k1_ecdsa_recoverable_signature_convert(
                context,
                &nonRecoverable,
                &recoverable
            )
        }
        
        return .init(raw: nonRecoverable)
    }
}

// MARK: Recover
extension FFI.ECDSA.Recovery {
    static func recover(
        _ wrapped: Wrapped,
        message: [UInt8]
    ) throws -> FFI.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw K1.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var rawSignature = wrapped.raw
        var rawPublicKey = secp256k1_pubkey()
        try FFI.call(
            ifFailThrow: .failedToRecoverPublicKey
        ) { context in
            secp256k1_ecdsa_recover(
                context,
                &rawPublicKey,
                &rawSignature,
                message
            )
        }
        return FFI.PublicKey.Wrapped(raw: rawPublicKey)
    }
}

// MARK: Sign
extension FFI.ECDSA.Recovery {
    
    /// Produces a **recoverable** ECDSA signature from a hashed `message`
    static func sign(
        hashedMessage: [UInt8],
        privateKey: K1.PrivateKey.Wrapped,
        options: K1.ECDSA.SigningOptions = .default
    ) throws -> FFI.ECDSA.Recovery.Wrapped {
       
        try FFI.ECDSA._sign(
            message: hashedMessage,
            privateKey: privateKey,
            options: options
        )
    }
}
