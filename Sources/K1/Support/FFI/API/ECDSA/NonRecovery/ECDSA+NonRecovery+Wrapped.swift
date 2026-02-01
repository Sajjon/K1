import Foundation
import Secp256k1

// MARK: - FFI.ECDSA.Wrapped
extension FFI.ECDSA {
	struct Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
		// swiftlint:disable:next nesting
		typealias Raw = secp256k1_ecdsa_signature
		let raw: Raw
		init(raw: Raw) {
			self.raw = raw
		}
	}
}

// MARK: Sign
extension FFI.ECDSA.Wrapped {
	// swiftlint:disable:next line_length
	static func sign() -> ECDSAFunctionPointer<Raw> {
		ecdsaSignNonRecoverable(context:outputSignature:hashedMessageBytes: privateKeyBytes:nonceFunctionPointer:arbitraryNonceData:)
	}
}

// MARK: ContiguousBytes
extension FFI.ECDSA.Wrapped {
	func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		var rawData = raw.data
		return try Swift.withUnsafeBytes(of: &rawData) { pointer in
			try body(pointer)
		}
	}
}
