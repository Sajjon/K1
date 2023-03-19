//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation

// MARK: - Curve

/// Details about the elliptic curve `secp256k1`.
public enum Curve {}

// MARK: - FiniteField
public extension Curve {
    /// The finite field of the secp256k1 curve.
    enum Field {}
}

public extension Curve.Field {
    /// Finite field members are 256 bits large, i.e. 32 bytes.
    static let byteCount = 32
}
