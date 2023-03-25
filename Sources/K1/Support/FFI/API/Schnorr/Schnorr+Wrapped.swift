import Foundation

extension FFI.Schnorr {
	struct Wrapped: @unchecked Sendable, Hashable {
		static let byteCount = 2 * Curve.Field.byteCount

		internal let bytes: [UInt8]

		init(bytes: [UInt8]) throws {
			guard bytes.count == Self.byteCount else {
				throw K1.Error.failedToInitSchnorrSignatureInvalidByteCount(
					got: bytes.count,
					expected: Self.byteCount
				)
			}
			self.bytes = bytes
		}
	}
}

// MARK: Serialization
extension FFI.Schnorr.Wrapped {
	var rawRepresentation: Data {
		Data(bytes)
	}
}

// MARK: Equatable
extension FFI.Schnorr.Wrapped {
	static func == (lhs: FFI.Schnorr.Wrapped, rhs: FFI.Schnorr.Wrapped) -> Bool {
		lhs.bytes == rhs.bytes
	}
}

// MARK: Hashable
extension FFI.Schnorr.Wrapped {
	func hash(into hasher: inout Hasher) {
		hasher.combine(bytes)
	}
}
