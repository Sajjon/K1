import Secp256k1

extension NormalizeSignatureOutcomeRaw {
	/// The checked signature was not normalized.
	static let wasntNormalized: Self = .SECP256K1_NORMALIZE_SIG_WASNT_NORMALIZED
}
