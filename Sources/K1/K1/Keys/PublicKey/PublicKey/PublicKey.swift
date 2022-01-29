//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

public extension K1 {
    
    struct PublicKey {
        
        private let wrapped: Wrapped

        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}

// MARK: - Convenience Init
// MARK: -
public extension K1.PublicKey {
    
    static func `import`<D: ContiguousBytes>(
        from data: D
    ) throws -> Self {
        try self.init(
            wrapped: .import(from: data)
        )
    }
    
}

public extension K1.PublicKey {

    var rawRepresentation: [UInt8] {
        wrapped.rawRepresentation
    }

    var format: K1.Format {
        wrapped.format
    }
}

