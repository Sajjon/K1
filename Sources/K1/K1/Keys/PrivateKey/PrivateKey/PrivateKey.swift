//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Crypto // swift-crypto

// MARK: - PrivateKey
// MARK: -

public extension K1 {
    
    struct PrivateKey: Sendable, Hashable {
        
        private let wrapped: Wrapped
		
        public let publicKey: PublicKey
            
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
            self.publicKey = PublicKey(wrapped: wrapped.publicKey)
        }
    }
}
public extension K1.PrivateKey {
	/// WARNING only use this if you really know what you are doing. This
	/// exposes the private key in raw form. Potentially devastatingly dangerous.
	var rawRepresentation: Data {
		withSecureBytes { Data($0) }
	}
}

internal extension K1.PrivateKey {

    func withSecureBytes<T>(function: @escaping (SecureBytes) throws -> T) rethrows -> T {
        try wrapped.withSecureBytes(function: function)
    }
}

// MARK: - Conveninence Init
// MARK: -
public extension K1.PrivateKey {
    
    static func generateNew() throws -> Self {
        let wrapped = try Wrapped.generateNew()
        return Self(wrapped: wrapped)
    }
    
    static func `import`<D: ContiguousBytes>(
        rawRepresentation: D
    ) throws -> Self {
        
        let wrapped = try Wrapped.import(
            from: rawRepresentation
        )
        
        return Self(wrapped: wrapped)
    }
}

// MARK: - Equatable
// MARK: -
public extension K1.PrivateKey {
    /// Two PrivateKey are considered equal if their PublicKeys are equal
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
}

// MARK: - Hashable
// MARK: -
public extension K1.PrivateKey {
    /// We use the public key of the private key as input to hash
    func hash(into hasher: inout Hasher) {
        hasher.combine(self.publicKey)
    }
}
