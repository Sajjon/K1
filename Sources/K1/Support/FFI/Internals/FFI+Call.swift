import CryptoKit
import secp256k1

// MARK: - FFI
final class FFI {
	let context: OpaquePointer
	init() throws {
		guard
			/* "Create a secp256k1 context object." */
			let context = secp256k1_context_create(Context.sign.rawValue | Context.verify.rawValue)
		else {
			throw K1.Error.failedToCreateContextForSecp256k1
		}

		self.context = context
	}

	deinit {
		secp256k1_context_destroy(context)
	}
}

extension FFI {
	static func toC<T>(
		_ closure: (FFI) throws -> T
	) throws -> T {
		let ffi = try FFI()
		return try closure(ffi)
	}

	/// Returns `true` iff result code is `1`
	func validate(
		_ method: (OpaquePointer) -> Int32
	) -> Bool {
		method(context) == 1
	}

	func callWithResultCode(
		_ method: (OpaquePointer) -> Int32
	) -> Int {
		let result = method(context)
		return Int(result)
	}

	func call(
		ifFailThrow error: K1.Error,
		_ method: (OpaquePointer) -> Int32
	) throws {
		let result = callWithResultCode(method)
		let successCode = 1
		guard result == successCode else {
			throw error
		}
	}

	static func call(
		ifFailThrow error: K1.Error,
		_ method: (OpaquePointer) -> Int32
	) throws {
		try toC { ffi in
			try ffi.call(ifFailThrow: error, method)
		}
	}
}
