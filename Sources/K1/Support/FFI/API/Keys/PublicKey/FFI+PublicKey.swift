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
		try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
			let expected = Self.x963ByteCount
			guard bufferPointer.count == expected else {
				throw K1.Error.incorrectKeySize
			}
			return try Self._deserialize(bytes: [UInt8](bufferPointer))
		}
	}

	/// `X || Y` (64 bytes)
	static func deserialize(
		rawRepresentation contiguousBytes: some ContiguousBytes
	) throws -> Wrapped {
		try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
			let expected = Self.rawByteCount
			guard bufferPointer.count == expected else {
				throw K1.Error.incorrectKeySize
			}
			return try Self.deserialize(x963Representation: [0x04] + [UInt8](bufferPointer))
		}
	}

	/// `02|03 || X` (33 bytes)
	static func deserialize(
		compressedRepresentation contiguousBytes: some ContiguousBytes
	) throws -> Wrapped {
		try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
			let expected = Self.compressedByteCount
			guard bufferPointer.count == expected else {
				throw K1.Error.incorrectKeySize
			}
			return try Self._deserialize(bytes: [UInt8](bufferPointer))
		}
	}

	private static func _deserialize(bytes: [UInt8]) throws -> Wrapped {
		var raw = PublicKeyRaw()
		try FFI.call(
			ifFailThrow: .publicKeyParse
		) { context in
			secp256k1_ec_pubkey_parse(
				context,
				&raw,
				bytes,
				bytes.count
			)
		}
		return .init(raw: raw)
	}
}

// MARK: Serialize
extension FFI.PublicKey {
	static func serialize(
		_ wrapped: Wrapped,
		format: K1.Format
	) throws -> Data {
		var byteCount = format.length
		var out = [UInt8](repeating: 0x00, count: byteCount)
		var publicKeyRaw = wrapped.raw
		try FFI.call(ifFailThrow: .publicKeySerialize) { context in
			secp256k1_ec_pubkey_serialize(
				context,
				&out,
				&byteCount,
				&publicKeyRaw,
				format.rawValue
			)
		}
		return Data(out.prefix(byteCount))
	}
}
