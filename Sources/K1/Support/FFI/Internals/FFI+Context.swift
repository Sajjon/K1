// FFI to C
import secp256k1

extension FFI {
	///  Bridging type used for underlying libsecp256k1 methods:
	///  - `secp256k1_context_create`
	///  - `secp256k1_context_preallocated_size`
	///  - `secp256k1_context_preallocated_create`
	enum Context: UInt32 {
		case none, sign, verify
	}
}

// MARK: Context
extension FFI.Context {
	/// Bridging value used by libsecp256k1 methods that requires info about
	/// how the context is used, e.g. for signing or verification (validate).
	var rawValue: UInt32 {
		let value: Int32

		switch self {
		case .none: value = SECP256K1_CONTEXT_NONE
		case .sign: value = SECP256K1_CONTEXT_SIGN
		case .verify: value = SECP256K1_CONTEXT_VERIFY
		}

		return UInt32(value)
	}
}
