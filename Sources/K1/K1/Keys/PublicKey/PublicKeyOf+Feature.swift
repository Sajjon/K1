//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-24.
//

import Foundation

// TODO: Replace typealiases and this single existential to use existentials generated with GYB.
public struct PublicKeyOf<Feature>: Sendable, Hashable, K1PublicKeyProtocol {
    
    public init(rawRepresentation: some ContiguousBytes) throws {
        try self.init(impl: .init(rawRepresentation: rawRepresentation))
    }
    
    public init(compressedRepresentation: some ContiguousBytes) throws {
        try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
    }
    
    public init(x963Representation: some ContiguousBytes) throws {
        try self.init(impl: .init(x963Representation: x963Representation))
    }
    
    public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
        try self.init(impl: .init(derRepresentation: derRepresentation))
    }
    
    public init(pemRepresentation: String) throws {
        try self.init(impl: .init(pemRepresentation: pemRepresentation))
    }
    
    public var rawRepresentation: Data {
        impl.rawRepresentation
    }
    
    public var x963Representation: Data {
        impl.x963Representation
    }
    
    public var derRepresentation: Data {
        impl.derRepresentation
    }
    
    public var compressedRepresentation: Data {
        impl.compressedRepresentation
    }
    
    public var pemRepresentation: String {
        impl.pemRepresentation
    }
    
    typealias Impl = K1.PublicKeyImpl
    internal let impl: Impl
    internal init(impl: Impl) {
        self.impl = impl
    }
}
