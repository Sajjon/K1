import Foundation
import Secp256k1

// MARK: - Raw
enum Raw {}

extension Raw {
	static func recoverableSignature(
		_ rawRepresentation: some DataProtocol
	) throws -> ECDSARecoverableSignatureRaw {
		let expected = K1.ECDSAWithKeyRecovery.Signature.Compact.byteCount
		guard
			rawRepresentation.count == expected
		else {
			throw K1.Error.incorrectParameterSize
		}
		var raw = ECDSARecoverableSignatureRaw()
		withUnsafeMutableBytes(of: &raw.data) { pointer in
			pointer.copyBytes(
				from: rawRepresentation.prefix(pointer.count)
			)
		}
		return raw
	}

	@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
	static func nonRecoverableSignature(
		compactBytes array: InlineArray<64, UInt8>
	) throws -> ECDSASignatureRaw {
		var raw = ECDSASignatureRaw()
		// FIXME: Declare a `parseEcdsaSignatureCompact` taking an InlineArray<64, UInt8> and use it directly
		try array.span.withUnsafeBufferPointer { compactBytes in
			try FFI.call(ifFailThrow: .ecdsaSignatureParseCompact) { context in
				parseEcdsaSignatureCompact(
					context: context,
					outputSignature: &raw,
					inputBytes: compactBytes
				)
			}
		}
		return raw
	}

	static func nonRecoverableSignature(
		compactBytes: [UInt8]
	) throws -> ECDSASignatureRaw {
		var raw = ECDSASignatureRaw()

		try FFI.call(ifFailThrow: .ecdsaSignatureParseCompact) { context in
			parseEcdsaSignatureCompact(
				context: context,
				outputSignature: &raw,
				inputBytes: compactBytes
			)
		}

		return raw
	}

	static func nonRecoverableSignature(
		derBytes: Span<UInt8>
	) throws -> ECDSASignatureRaw {
		var raw = ECDSASignatureRaw()

		try FFI.call(ifFailThrow: .ecdsaSignatureParseDER) { context in
			parseEcdsaSignatureDER(context: context, outputSignature: &raw, input: derBytes)
		}

		return raw
	}
}
