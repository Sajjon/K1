//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import BigInt

internal extension K1.PrivateKey {
    
    @usableFromInline
    struct Wrapped {
        
        private let secureBytes: SecureBytes
        
        /// Allowing for "lazy" computation of public key. This is a workaround
        /// the fact that (immutable instances of) structs cannot have lazy
        /// properties.
        private let _publicKey: MemoizationBox<K1.PublicKey.Wrapped> = .init()
   
        private init(
            secureBytes: SecureBytes
        ) throws {
            guard case 1..<K1.Curve.order = BigUInt(Data(secureBytes)) else {
                throw K1.Error.invalidPrivateKeyNotWithinBounds
            }
            self.secureBytes = secureBytes
        }
    }
    
}


internal extension K1.PrivateKey.Wrapped {
    
    /// The computed public key of this private key.
    @usableFromInline
    var publicKey: K1.PublicKey.Wrapped {
        _publicKey.getOrEvaluate {
            do {
                return try K1.PublicKey.Wrapped.derive(privateKeyBytes: secureBytes.bytes)
            } catch {
                fatalError("Should always be able to derive public key from private key, but got underlying error: \(error)")
            }
        }
    }
    
    static func `import`(
        from privateKeyBytes: [UInt8]
    ) throws -> Self {
        try .init(secureBytes: SecureBytes(privateKeyBytes))
    }
    
    static func `import`<D: ContiguousBytes>(
        from data: D
    ) throws -> Self {
        try .import(
            from: data.bytes
        )
    }
    
    /// Generate a new private key from randomness.
    @usableFromInline
    static func generateNew() throws -> Self {
        
        var attempt = 0
        
        while attempt < 100 {
            defer { attempt += 1 }
            do {
                let secureBytes = SecureBytes(count: Self.byteCount)
                let privateKey = try Self(secureBytes: secureBytes)
                // Success => return valid private key
                return privateKey
            } catch {
                // Failure (due to unlikely scenario that the private key scalar > order of the curve) => retry
            }
        }
        
        // Probability of this happening is:
        // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        // (n / 2^256) ^ 100 = lim 0
        // I.e. will not happen.
        fatalError("""
            Failed to generate private key after #\(attempt) attempts.
            You are the most unlucky person in the universe.
            Or by Occam's razor: the person writing this code made some error.
            """
        )
    }
}

internal extension K1.PrivateKey.Wrapped {
    
    func withSecureBytes<T>(function: (SecureBytes) throws -> T) rethrows -> T {
        try function(secureBytes)
    }
}

internal extension K1.PrivateKey.Wrapped {
    static let byteCount = K1.Curve.Field.byteCount

}
