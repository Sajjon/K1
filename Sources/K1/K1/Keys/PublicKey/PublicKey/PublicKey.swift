//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


public extension K1 {
    
    struct PublicKey: Equatable {
        
        private let wrapped: Wrapped

        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}

internal extension K1.PublicKey {
    var uncompressedRaw: [UInt8] {
        wrapped.uncompressedRaw
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
    
    func rawRepresentation(format: K1.Format) throws -> [UInt8] {
        try wrapped.rawRepresentation(format: format)
    }
    

}

