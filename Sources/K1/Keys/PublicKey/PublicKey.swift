//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

extension K1 {
    
    public struct PublicKey: Sendable, Hashable {
        
        typealias Wrapped = FFI.PublicKey.Wrapped
        internal let wrapped: Wrapped
        
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}

// MARK: Init
extension K1.PublicKey {
    
    public init(x963Representation: some ContiguousBytes) throws  {
        try self.init(wrapped: FFI.PublicKey.from(x963Representation: x963Representation))
    }
}

// MARK: Serialize
extension K1.PublicKey {
    public func rawRepresentation(format: K1.Format) throws -> Data {
        try wrapped.rawRepresentation(format: format)
    }
}

// MARK: Equatable
extension K1.PublicKey {
    public static func == (lhsSelf: Self, rhsSelf: Self) -> Bool {
        let lhs = lhsSelf.wrapped
        let rhs = rhsSelf.wrapped
        do {
            return try lhs.compare(to: rhs)
        } catch {
            return lhs.withUnsafeBytes { lhsBytes in
                rhs.withUnsafeBytes { rhsBytes in
                    safeCompare(lhsBytes, rhsBytes)
                }
            }
        }
    }
}

// MARK: Hashable
extension K1.PublicKey {
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}
