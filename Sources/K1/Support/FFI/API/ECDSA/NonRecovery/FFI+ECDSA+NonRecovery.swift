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

	/// Compact aka `IEEE P1363` aka `R||S`.
	@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
	static func from(
		compactBytes array64: InlineArray<64, UInt8>
	) throws -> Wrapped {
		try Wrapped(
			raw: Raw.nonRecoverableSignature(compactBytes: array64)
		)
	}

	static func from(
		derRepresentation: [UInt8]
	) throws -> Wrapped {
		try withSpanFromArray(derRepresentation) { span in
			try Self.from(derRepresentation: span)
		}
	}

	static func from(
		derRepresentation: Span<UInt8>
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
		FFI.call { context in
			serializeEcdsaSignatureCompact(
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
			serializeEcdsaSignatureDER(
				context: context,
				outputBytes: &derSignature,
				outputByteCount: &derMaxLength,
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
	) -> Bool {
		FFI.toC { ffi -> Bool in
			var publicKeyRaw = publicKey.raw
			var maybeMalleable = signature.raw
			var normalized = ECDSASignatureRaw()

			let signatureWasMalleable = ffi.call { context in
				normalizeEcdsaSignature(context: context, outputSignature: &normalized, inputSignature: &maybeMalleable)
			} == .wasntNormalized

			let isSignatureValid = ffi.call { context in
				verifyEcdsaSignature(
					context: context,
					signature: &normalized,
					messageHash: message,
					publicKey: &publicKeyRaw
				)
			} == .signatureValid

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
