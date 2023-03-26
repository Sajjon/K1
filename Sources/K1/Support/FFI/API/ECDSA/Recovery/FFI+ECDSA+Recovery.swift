import Foundation
import secp256k1

// MARK: Deserialize
extension FFI.ECDSA.Recoverable {
	static let byteCount = FFI.ECDSA.NonRecoverable.byteCount + 1

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
			ifFailThrow: .recoverableSignatureParseCompact
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
extension FFI.ECDSA.Recoverable {
	static func serializeCompact(
		_ wrapped: Wrapped
	) throws -> (rs: [UInt8], recoveryID: Int32) {
		var rs = [UInt8](repeating: 0, count: FFI.ECDSA.NonRecoverable.byteCount)
		var recoveryID: Int32 = 0
		var rawSignature = wrapped.raw
		try FFI.call(
			ifFailThrow: .recoverableSignatureSerializeCompact
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
extension FFI.ECDSA.Recoverable {
	static func nonRecoverable(
		_ wrapped: Wrapped
	) throws -> FFI.ECDSA.NonRecoverable.Wrapped {
		var nonRecoverable = secp256k1_ecdsa_signature()
		var recoverable = wrapped.raw

		try FFI.call(
			ifFailThrow: .recoverableSignatureConvert
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
extension FFI.ECDSA.Recoverable {
	static func recover(
		_ wrapped: Wrapped,
		message: [UInt8]
	) throws -> FFI.PublicKey.Wrapped {
		guard message.count == Curve.Field.byteCount else {
			throw K1.Error.incorrectParameterSize
		}
		var rawSignature = wrapped.raw
		var rawPublicKey = secp256k1_pubkey()
		try FFI.call(
			ifFailThrow: .recover
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

// MARK: Validate
extension FFI.ECDSA.Recoverable {
	static func isValid(
		signature: FFI.ECDSA.Recoverable.Wrapped,
		publicKey: FFI.PublicKey.Wrapped,
		message: [UInt8],
		options: K1.ECDSA.ValidationOptions = .default
	) throws -> Bool {
		do {
			let publicKeyNonRecoverable = FFI.PublicKey.Wrapped(raw: publicKey.raw)
			let signatureNonRecoverable = try FFI.ECDSA.Recoverable.nonRecoverable(signature)
			return try FFI.ECDSA.NonRecoverable.isValid(
				signature: signatureNonRecoverable,
				publicKey: publicKeyNonRecoverable,
				message: message,
				options: options
			)
		} catch {
			return false
		}
	}
}

// MARK: Sign
extension FFI.ECDSA.Recoverable {
	/// Produces a **recoverable** ECDSA signature from a hashed `message`
	static func sign(
		hashedMessage: [UInt8],
		privateKey: K1._PrivateKeyImplementation.Wrapped,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> FFI.ECDSA.Recoverable.Wrapped {
		try FFI.ECDSA._sign(
			message: hashedMessage,
			privateKey: privateKey,
			options: options
		)
	}
}
