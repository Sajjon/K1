import Foundation
import Secp256k1

// MARK: Deserialize
extension FFI.ECDSAWithKeyRecovery {
	static let byteCount = FFI.ECDSA.byteCount + 1

	static func deserialize(
		rawRepresentation: some DataProtocol
	) throws -> Wrapped {
		try Wrapped(raw: Raw.recoverableSignature(rawRepresentation))
	}

	/// Compact aka `IEEE P1363` aka `R||S`.
	static func deserialize(
		// swiftlint:disable:next identifier_name
		compact rs: [UInt8],
		recoveryID recid: Int32
	) throws -> Wrapped {
		var raw = Wrapped.Raw()
		try FFI.call(
			ifFailThrow: .recoverableSignatureParseCompact
		) { context in
			parseRecoverableECDSASignatureFromCompactBytes(
				context: context,
				outputRecoveredSignature: &raw,
				compactBytes: rs,
				recoveryID: recid
			)
		}
		return .init(raw: raw)
	}
}

// MARK: Serialize
extension FFI.ECDSAWithKeyRecovery {
	static func serializeCompact(
		_ wrapped: Wrapped
	) -> (rs: [UInt8], recoveryID: Int32) {
		// swiftlint:disable:next identifier_name
		var rs = [UInt8](repeating: 0, count: FFI.ECDSA.byteCount)
		var recoveryID: Int32 = 0
		var rawSignature = wrapped.raw
		FFI.call { context in
			serializeRecoverableECDSASignatureCompact(
				context: context,
				outputBytes: &rs,
				recoveryID: &recoveryID,
				recoverableSignature: &rawSignature
			)
		}
		return (rs, recoveryID)
	}
}

// MARK: Convert
extension FFI.ECDSAWithKeyRecovery {
	/// Convert a recoverable signature into a normal signature.
	static func nonRecoverable(
		_ wrapped: Wrapped
	) -> FFI.ECDSA.Wrapped {
		var nonRecoverable = ECDSASignatureRaw()
		var recoverable = wrapped.raw

		FFI.call { context in
			ecdsaRecoverableSignatureToNonRecoverable(
				context: context,
				outputNonRecoverableSignature: &nonRecoverable,
				recoverableSignature: &recoverable
			)
		}

		return .init(raw: nonRecoverable)
	}
}

// MARK: Recover
extension FFI.ECDSAWithKeyRecovery {
	static func recover(
		_ wrapped: Wrapped,
		message: [UInt8]
	) throws -> FFI.PublicKey.Wrapped {
		guard message.count == Curve.Field.byteCount else {
			throw K1.Error.incorrectParameterSize
		}
		var rawSignature = wrapped.raw
		var rawPublicKey = PublicKeyRaw()
		try FFI.call(
			ifFailThrow: .recover
		) { context in
			recoverPublicKeyFromECDSASignature(
				context: context,
				publicKey: &rawPublicKey,
				signature: &rawSignature,
				hashedMessage: message
			)
		}
		return FFI.PublicKey.Wrapped(raw: rawPublicKey)
	}
}

// MARK: Validate
extension FFI.ECDSAWithKeyRecovery {
	static func isValid(
		signature: FFI.ECDSAWithKeyRecovery.Wrapped,
		publicKey: FFI.PublicKey.Wrapped,
		message: [UInt8],
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		let publicKeyNonRecoverable = FFI.PublicKey.Wrapped(raw: publicKey.raw)
		let signatureNonRecoverable = FFI.ECDSAWithKeyRecovery.nonRecoverable(signature)
		return FFI.ECDSA.isValid(
			signature: signatureNonRecoverable,
			publicKey: publicKeyNonRecoverable,
			message: message,
			options: options
		)
	}
}

// MARK: Sign
extension FFI.ECDSAWithKeyRecovery {
	/// Produces a **recoverable** ECDSA signature from a hashed `message`
	static func sign(
		hashedMessage: [UInt8],
		privateKey: K1._PrivateKeyImplementation.Wrapped,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> FFI.ECDSAWithKeyRecovery.Wrapped {
		try FFI._ecdsa(
			message: hashedMessage,
			privateKey: privateKey,
			options: options
		)
	}
}
