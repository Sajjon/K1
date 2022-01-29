import BigInt

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

internal extension K1.Curve {
    
    /// The order of the secp256k1 curve, i.e. how many elements that exist in
    /// this group.
    static let order = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!
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
