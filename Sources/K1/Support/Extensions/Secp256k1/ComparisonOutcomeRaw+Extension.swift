import Secp256k1

/// Outcome of comparing two values with each other
enum ComparisonOutcome {
	/// The compared values are equal.
	case equal

	/// The RHS of the compared values is greater than the LHS.
	case lhsIsGreater

	/// The RHS of the compared values is greater than the LHS.
	case rhsIsGreater
}

extension ComparisonOutcome {
	init(raw: ComparisonOutcomeRaw) {
		switch raw {
		case .SECP256K1_PUBKEY_CMP_EQUAL: self = .equal
		case .SECP256K1_PUBKEY_CMP_LHS_IS_GREATER: self = .lhsIsGreater
		case .SECP256K1_PUBKEY_CMP_RHS_IS_GREATER: self = .rhsIsGreater
		}
	}
}
