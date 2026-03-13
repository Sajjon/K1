import Secp256k1

extension VerifySignatureOutcomeRaw {
	/// The checked Signature is valid.
	static let signatureValid: Self = .SECP256K1_VERIFY_SIG_CORRECT

	/// The checked Signature is invalid or we failed to parse it.
	static let signatureInvalid: Self = .SECP256K1_VERIFY_SIG_UNPARSABLE_OR_INCORRECT
}
