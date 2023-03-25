import Foundation
import secp256k1

// MARK: - FFI.ECDSA.NonRecovery.Wrapped
extension FFI.ECDSA.NonRecovery {
	struct Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
		typealias Raw = secp256k1_ecdsa_signature
		let raw: Raw
		init(raw: Raw) {
			self.raw = raw
		}
	}
}

// MARK: Sign
extension FFI.ECDSA.NonRecovery.Wrapped {
	static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
		secp256k1_ecdsa_sign
	}
}

// MARK: ContiguousBytes
extension FFI.ECDSA.NonRecovery.Wrapped {
	func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		var rawData = raw.data
		return try Swift.withUnsafeBytes(of: &rawData) { pointer in
			try body(pointer)
		}
	}
}
