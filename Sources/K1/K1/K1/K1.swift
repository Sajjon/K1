import Foundation

// MARK: - `K1` (secp256k1)
// MARK: -

/// The Elliptic Curve `secp256k1`
public enum K1 {}

// MARK: - Curve
// MARK: -
internal extension K1 {
    
    /// Details about the elliptic curve `secp256k1`.
    enum Curve {}
}

// MARK: - FiniteField
// MARK: -
internal extension K1.Curve {
    /// The finite field of the secp256k1 curve.
    enum Field {}
}

internal extension K1.Curve.Field {
    /// Finite field members are 256 bits large, i.e. 32 bytes.
    static let byteCount = 32
}
