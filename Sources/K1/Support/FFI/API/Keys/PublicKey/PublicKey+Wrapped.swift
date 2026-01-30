import Foundation
import Secp256k1

// MARK: - FFI.PublicKey
extension FFI {
	enum PublicKey {}
}

// MARK: - FFI.PublicKey.Wrapped
extension FFI.PublicKey {
	struct Wrapped: @unchecked Sendable, ContiguousBytes {
		// swiftlint:disable:next nesting
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

// MARK: Group Operations
extension FFI.PublicKey.Wrapped {
	/// Adds two public keys (points) on the secp256k1 curve
	static func + (lhs: Self, rhs: Self) throws -> Self {
		try sum(keys: [lhs, rhs])
	}

	/// Subtracts two public keys (points) on the secp256k1 curve
	static func - (lhs: Self, rhs: Self) throws -> Self {
		try lhs + rhs.negate()
	}

	/// Negates a public key (point) on the secp256k1 curve
	func negate() throws -> Self {
		var result = self.raw
		try FFI.toC { ffi in
			try ffi.call(ifFailThrow: .publicKeyCreate) { context in
				secp256k1_ec_pubkey_negate(context, &result)
			}
		}
		return Self(raw: result)
	}

	/// Combines multiple public keys (points) on the secp256k1 curve
	static func sum(keys: [Self]) throws -> Self {
		guard !keys.isEmpty else {
			throw K1.Error.invalidParameter
		}

		var result = secp256k1_pubkey()
		var mutableKeys = keys.map(\.raw)

		try mutableKeys.withUnsafeMutableBufferPointer { keysBuffer in
			var keyPointers = [UnsafePointer<secp256k1_pubkey>?]()
			keyPointers.reserveCapacity(keys.count)

			for index in 0 ..< keys.count {
				keyPointers.append(keysBuffer.baseAddress!.advanced(by: index))
			}

			try keyPointers.withUnsafeBufferPointer { pointers in
				try FFI.toC { ffi in
					try ffi.call(ifFailThrow: .groupOperation) { context in
						secp256k1_ec_pubkey_combine(context, &result, pointers.baseAddress!, keys.count)
					}
				}
			}
		}
		return Self(raw: result)
	}
}
