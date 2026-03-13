import Foundation
import K1Macros
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
}

// MARK: NonRecoverable Compact
extension Raw {

	@declareSafeApi(byteCount: 64)
	static func __nonRecoverableSignature(
		compactBytes: UnsafePointer<UInt8>
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
}

// MARK: NonRecoverable DER
extension Raw {
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
