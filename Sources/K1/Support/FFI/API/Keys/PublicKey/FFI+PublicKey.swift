import Foundation
import Secp256k1

// MARK: Deserialize
extension FFI.PublicKey {
	/// `04 || X || Y` (65 bytes)
	public static let x963ByteCount = 1 + (2 * Curve.Field.byteCount)

	/// `X || Y` (64 bytes)
	public static let rawByteCount = 2 * Curve.Field.byteCount

	/// `02|03 || X` (33 bytes)
	public static let compressedByteCount = 1 + Curve.Field.byteCount

	/// `04 || X || Y` (65 bytes)
	static func deserialize(
		x963Representation contiguousBytes: some ContiguousBytes
	) throws -> Wrapped {
		try withSpanFromContiguousBytes(contiguousBytes) { span in
			let expected = Self.x963ByteCount
			guard span.count == expected else {
				throw K1.Error.incorrectKeySize
			}
			return try Self._deserialize(span: span)
		}
	}

	/// `X || Y` (64 bytes)
	static func deserialize(
		rawRepresentation contiguousBytes: some ContiguousBytes
	) throws -> Wrapped {
		try withSpanFromContiguousBytes(contiguousBytes) { span in
			let expected = Self.rawByteCount
			guard span.count == expected else {
				throw K1.Error.incorrectKeySize
			}
			// Prepend 0x04 prefix into a small temporary buffer
			var prefixed = [UInt8](repeating: 0, count: expected + 1)
			prefixed[0] = 0x04
			for index in 0 ..< span.count {
				prefixed[index + 1] = span[index]
			}
			return try prefixed.withUnsafeBufferPointer { buf in
				try Self._deserialize(span: Span(_unsafeElements: buf))
			}
		}
	}

	/// `02|03 || X` (33 bytes)
	static func deserialize(
		compressedRepresentation contiguousBytes: some ContiguousBytes
	) throws -> Wrapped {
		try withSpanFromContiguousBytes(contiguousBytes) { span in
			let expected = Self.compressedByteCount
			guard span.count == expected else {
				throw K1.Error.incorrectKeySize
			}
			return try Self._deserialize(span: span)
		}
	}

	static func deserialize(
		compressedRepresentation span: Span<UInt8>
	) throws -> Wrapped {
		try _deserialize(span: span)
	}

	private static func _deserialize(span: Span<UInt8>) throws -> Wrapped {
		var raw = PublicKeyRaw()
		try FFI.call(
			ifFailThrow: .publicKeyParse
		) { context in
			parsePublicKey(context: context, outputPublicKey: &raw, inputBytes: span)
		}
		return .init(raw: raw)
	}
}

// MARK: Serialize
extension FFI.PublicKey {
	static func serialize(
		_ wrapped: Wrapped,
		format: K1.Format
	) -> Data {
		var byteCount = format.length
		var out = [UInt8](repeating: 0x00, count: byteCount)
		var publicKeyRaw = wrapped.raw
		FFI.call { context in
			serializePublicKey(
				context: context,
				outputBytes: &out,
				outputByteCount: &byteCount,
				publicKey: &publicKeyRaw,
				formatFlags: format.rawValue
			)
		}
		return Data(out.prefix(byteCount))
	}
}
