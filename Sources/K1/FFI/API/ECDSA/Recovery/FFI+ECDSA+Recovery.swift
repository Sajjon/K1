import Foundation
import secp256k1

// MARK: Deserialize
extension FFI.ECDSA.Recovery {
    static let byteCount = FFI.ECDSA.NonRecovery.byteCount + 1
    
    static func from(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(raw: Raw.recoverableSignature(rawRepresentation))
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
}


// MARK: Serialize
extension FFI.ECDSA.Recovery {
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
}

// MARK: Convert
extension FFI.ECDSA.Recovery {
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

// MARK: Recover
extension FFI.ECDSA.Recovery {
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
}

// MARK: Sign
extension FFI.ECDSA.Recovery {
    
    /// Produces a **recoverable** ECDSA signature from a hashed `message`
    static func sign(
        hashedMessage: [UInt8],
        privateKey: K1.PrivateKey.Wrapped,
        input: K1.ECDSA.SigningInput = .default
    ) throws -> FFI.ECDSA.Recovery.Wrapped {
       
        try FFI.ECDSA._sign(
            message: hashedMessage,
            privateKey: privateKey,
            input: input
        )
    }
}
