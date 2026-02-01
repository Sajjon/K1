import Foundation
import Secp256k1

// MARK: Deserialize
extension FFI.ECDSA {
	static let byteCount = 2 * Curve.Field.byteCount

	/// Compact aka `IEEE P1363` aka `R||S`.
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
extension FFI.ECDSA {
	static func compact(_ wrapped: Wrapped) throws -> Data {
		var out = [UInt8](repeating: 0, count: Self.byteCount)
		var rawSignature = wrapped.raw
		try FFI.call(ifFailThrow: .ecdsaSignatureSerializeCompact) { context in
			serializeRecoverableECDSASignatureCompact(
				context: context,
				outputBytes: &out,
				signature: &rawSignature
			)
		}
		return Data(out)
	}

	static func der(
		_ wrapped: Wrapped
	) throws -> Data {
		var derMaxLength = 75 // in fact max is 73, but we can have some margin.
		var derSignature = [UInt8](repeating: 0, count: derMaxLength)
		var rawSignature = wrapped.raw
		try FFI.call(ifFailThrow: .ecdsaSignatureSerializeDER) { context in
			serializeECDSASignatureDER(
				context: context,
				outputBytes: &derSignature,
				length: &derMaxLength,
				signature: &rawSignature
			)
		}
		return Data(derSignature.prefix(derMaxLength))
	}
}

// MARK: Recover
extension FFI.ECDSA {
	static func recoverPublicKey(
		_ wrapped: Wrapped,
		recoveryID: Int32,
		message: [UInt8]
	) throws -> FFI.PublicKey.Wrapped {
		guard message.count == Curve.Field.byteCount else {
			throw K1.Error.incorrectParameterSize
		}
		let nonRecoverableCompact = try FFI.ECDSA.compact(wrapped)
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
			throw K1.Error.incorrectParameterSize
		}
		var compact = [UInt8](nonRecoverableCompact)
		var recovered = ECDSARecoverableSignatureRaw()
		try FFI.call(ifFailThrow: .recoverableSignatureParseCompact) { context in
			parseRecoverableECDSASignatureFromCompactBytes(
				context: context,
				outputRecoveredSignature: &recovered,
				compactBytes: &compact,
				recoveryID: recoveryID
			)
		}
		var publicKeyRaw = PublicKeyRaw()
		try FFI.call(ifFailThrow: .recover) { context in
			recoverPublicKeyFromECDSASignature(
				context: context,
				publicKey: &publicKeyRaw,
				signature: &recovered,
				hashedMessage: message
			)
		}
		return FFI.PublicKey.Wrapped(raw: publicKeyRaw)
	}
}

// MARK: Validate
extension FFI.ECDSA {
	static func isValid(
		signature: FFI.ECDSA.Wrapped,
		publicKey: FFI.PublicKey.Wrapped,
		message: [UInt8],
		options: K1.ECDSA.ValidationOptions = .default
	) throws -> Bool {
		try FFI.toC { ffi -> Bool in
			var publicKeyRaw = publicKey.raw
			var maybeMalleable = signature.raw
			var normalized = ECDSASignatureRaw()

			let codeForSignatureWasMalleable = 1
			let signatureWasMalleableResult = ffi.callWithResultCode { context in
				secp256k1_ecdsa_signature_normalize(context, &normalized, &maybeMalleable)
			}
			let signatureWasMalleable = signatureWasMalleableResult == codeForSignatureWasMalleable
			let isSignatureValid = ffi.validate { context in
				secp256k1_ecdsa_verify(
					context,
					&normalized,
					message,
					&publicKeyRaw
				)
			}
			let acceptMalleableSignatures = options.malleabilityStrictness == .accepted
			switch (isSignatureValid, signatureWasMalleable, acceptMalleableSignatures) {
			case (true, false, _):
				// Signature is valid
				return true
			case (true, true, true):
				// Signature was valid but malleable, since you specified to
				// accept malleability => considering signature valid.
				return true
			case (true, true, false):
				// Signature was valid, but not normalized which was required =>
				// considering signature invalid.
				return false
			case (false, _, _):
				// Signature is invalid.
				return false
			}
		}
	}
}

// MARK: Sign
extension FFI.ECDSA {
	/// Produces a **non recoverable** ECDSA signature from a hashed `message`
	static func sign(
		hashedMessage: [UInt8],
		privateKey: FFI.PrivateKey.Wrapped,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> FFI.ECDSA.Wrapped {
		try FFI._ecdsa(
			message: hashedMessage,
			privateKey: privateKey,
			options: options
		)
	}
}
