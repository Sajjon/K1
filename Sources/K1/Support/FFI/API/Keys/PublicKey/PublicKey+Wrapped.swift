import Foundation
import secp256k1

// MARK: - FFI.PublicKey
extension FFI {
	enum PublicKey {}
}

// MARK: - FFI.PublicKey.Wrapped
extension FFI.PublicKey {
	struct Wrapped: @unchecked Sendable, ContiguousBytes {
		typealias Raw = secp256k1_pubkey
		let raw: Raw
		init(raw: Raw) {
			self.raw = raw
		}
	}
}

// MARK: ContiguousBytes
extension FFI.PublicKey.Wrapped {
	func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		var rawData = raw.data
		return try Swift.withUnsafeBytes(of: &rawData) { pointer in
			try body(pointer)
		}
	}
}

// MARK: Comparison
extension FFI.PublicKey.Wrapped {
	func compare(to other: FFI.PublicKey.Wrapped) throws -> Bool {
		var selfRaw = self.raw
		var otherRaw = other.raw
		return try FFI.toC { ffi in
			ffi.callWithResultCode { context in
				secp256k1_ec_pubkey_cmp(context, &selfRaw, &otherRaw)
			} == 0
		}
	}
}
