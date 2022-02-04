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
    
    struct PrivateKey: Equatable {
        
        private let wrapped: Wrapped
        
        public let publicKey: PublicKey
            
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
            self.publicKey = PublicKey(wrapped: wrapped.publicKey)
        }
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
    static func == (lhs: Self, rhs: Self) -> Bool {
        var equals = false
        lhs.withSecureBytes { lhsSecureBytes in
            rhs.withSecureBytes { rhsSecureBytes in
                equals = lhsSecureBytes == rhsSecureBytes
            }
        }
        return equals
    }
}
