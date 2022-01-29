//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

internal extension K1.PublicKey {
    
    @usableFromInline
    struct Wrapped {
        
        @usableFromInline
        let rawRepresentation: [UInt8]
        
        @usableFromInline
        let format: K1.Format
    
        internal init(
            publicKeyRaw: [UInt8]
        ) throws {
            self.rawRepresentation = publicKeyRaw
            self.format = try K1.Format(byteCount: publicKeyRaw.count)
        }
    }
}

extension K1.PublicKey.Wrapped {
    
    static func `import`<D: ContiguousBytes>(
        from raw: D)
    throws -> Self {
        try .import(from: raw.bytes)
    }
    
}
