import Foundation

// MARK: - Curve
/// Details about the elliptic curve `secp256k1`.
enum Curve {}

// MARK: Curve.Field
extension Curve {
	/// The finite field of the secp256k1 curve.
	enum Field {}
}

extension Curve.Field {
	/// Finite field members are 256 bits large, i.e. 32 bytes.
	static let byteCount = 32
}
