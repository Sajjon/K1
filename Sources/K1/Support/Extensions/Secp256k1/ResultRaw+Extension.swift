import Secp256k1

extension ResultRaw {
	/// The call to the `secp256k1` function returned with successful result.
	static let success: Self = .SECP256K1_RESULT_SUCCESS

	/// The call to the `secp256k1` function returned with failure result.
	static let failure: Self = .SECP256K1_RESULT_FAILURE
}
