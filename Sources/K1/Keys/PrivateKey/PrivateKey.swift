//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import CryptoKit
import Foundation

// MARK: - PrivateKey
extension K1 {
    
    public struct PrivateKey: Sendable, Hashable {
        
        typealias Wrapped = FFI.PrivateKey.Wrapped
        internal let wrapped: Wrapped
        
        public let publicKey: PublicKey
        
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
            self.publicKey = PublicKey(wrapped: wrapped.publicKey)
        }
    }
}

// MARK: Inits
extension K1.PrivateKey {
    
    public init(
        rawRepresentation: some DataProtocol
    ) throws {
        try self.init(wrapped: FFI.PrivateKey.from(rawRepresentation: rawRepresentation))
    }
    
    public init() {
        self.init(wrapped: .init())
    }
}


// MARK: - Equatable
extension K1.PrivateKey {
    /// Two PrivateKey are considered equal if their PublicKeys are equal
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
}

// MARK: - Hashable
extension K1.PrivateKey {
    /// We use the public key of the private key as input to hash
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.publicKey)
    }
}
