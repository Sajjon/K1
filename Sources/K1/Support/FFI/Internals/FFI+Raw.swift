import Foundation
import secp256k1

// MARK: - Raw
enum Raw {}

extension Raw {
	static func recoverableSignature(
		_ rawRepresentation: some DataProtocol
	) throws -> secp256k1_ecdsa_recoverable_signature {
		let expected = K1.ECDSA.Recoverable.Signature.Compact.byteCount
		guard
			rawRepresentation.count == expected
		else {
			throw K1.Error.incorrectParameterSize
		}
		var raw = secp256k1_ecdsa_recoverable_signature()
		withUnsafeMutableBytes(of: &raw.data) { pointer in
			pointer.copyBytes(
				from: rawRepresentation.prefix(pointer.count)
			)
		}
		return raw
	}

	static func nonRecoverableSignature(
		compactBytes: [UInt8]
	) throws -> secp256k1_ecdsa_signature {
		var raw = secp256k1_ecdsa_signature()

		try FFI.call(ifFailThrow: .ecdsaSignatureParseCompact) { context in
			secp256k1_ecdsa_signature_parse_compact(
				context,
				&raw,
				compactBytes
			)
		}

		return raw
	}

	static func nonRecoverableSignature(
		derBytes: [UInt8]
	) throws -> secp256k1_ecdsa_signature {
		var raw = secp256k1_ecdsa_signature()

		try FFI.call(ifFailThrow: .ecdsaSignatureParseDER) { context in
			secp256k1_ecdsa_signature_parse_der(
				context,
				&raw,
				derBytes,
				derBytes.count
			)
		}

		return raw
	}
}
