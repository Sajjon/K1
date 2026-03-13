import CryptoKit
import Secp256k1

/// `secp256k1_context`
///
/// In the best of worlds this would not be a typealias
/// for an `OpaquePointer`, mapping to a Swift class using
/// apinotes have been attempted without success, seems the
/// implementation of `secp256k1` prevents it.
///
/// An `UnsafePointer<secp256k1_context_create>` would also
/// have been better, but mapping to it using apinotes also
/// failed.
typealias Secp256k1ContextRaw = OpaquePointer

// MARK: - FFI

/// A swift wrapper around an `OpaquePointer` to `secp256k1_context`
/// created with `secp256k1_context_create`.
///
/// In the best of worlds this would not be a typealias
/// for an `OpaquePointer`, mapping to a Swift class using
/// apinotes have been attempted without success, seems the
/// implementation of `secp256k1` prevents it.
///
/// An `UnsafePointer<secp256k1_context_create>` would also
/// have been better, but mapping to it using apinotes also
/// failed.
final class FFI {
	/// The wrapped `secp256k1_context` (`OpaquePointer`).
	let context: Secp256k1ContextRaw

	/// Creates a new `secp256k1_context` using `secp256k1_context_create` to be used
	/// for both signing and verification operations.
	///
	/// Will crash if `secp256k1_context_create` fails, which it never should.
	init() {
		guard
			// Create secp256k1 context object
			let context = createContext(flags: Context.sign.rawValue | Context.verify.rawValue)
		else {
			fatalError(
				"""
				Failed to create context, did you run out of memory? 

				`secp256k1_context_create` call failed. Which under most circumstances should never ever happen.

				Please report a bug at:
				https://github.com/Sajjon/K1/issues/new

				And provide OS and Swift version details.
				"""
			)
		}

		self.context = context
	}

	deinit {
		destroyContext(context)
	}
}

// MARK: Helper Methods
extension FFI {
	func call(
		ifFailThrow error: FFI.Error,
		_ method: (Secp256k1ContextRaw) -> ResultRaw
	) throws {
		guard method(context) == ResultRaw.success else {
			throw K1.Error.underlyingLibsecp256k1Error(error)
		}
	}

	func call<R>(
		_ method: (OpaquePointer) throws -> R
	) rethrows -> R {
		try method(context)
	}

	func callGetResult(
		_ method: (OpaquePointer) -> ResultRaw
	) -> ResultRaw {
		method(context)
	}
}

// MARK: - Static
extension FFI {
	static func toC<R>(
		_ body: (FFI) throws -> R
	) rethrows -> R {
		try body(FFI())
	}

	static func call<R>(
		_ method: @escaping (OpaquePointer) throws -> R
	) rethrows -> R {
		try method(FFI().context)
	}

	static func callGetResult(
		_ method: (OpaquePointer) -> ResultRaw
	) -> ResultRaw {
		FFI().callGetResult(method)
	}

	static func call(
		ifFailThrow error: FFI.Error,
		_ method: (OpaquePointer) -> ResultRaw
	) throws {
		try FFI().call(ifFailThrow: error, method)
	}

	static func call(
		_ method: @escaping (OpaquePointer) -> Int32
	) {
		_ = method(FFI().context)
	}
}
