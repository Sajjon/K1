//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-24.
//

import Foundation

public struct PrivateKeyOf<Feature>: Sendable, Hashable, K1PrivateKeyProtocol {
    public init() {
        self.init(impl: .init())
    }
    
    public init(rawRepresentation: some ContiguousBytes) throws {
        try self.init(impl: .init(rawRepresentation: rawRepresentation))
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
    
    public var pemRepresentation: String {
        impl.pemRepresentation
    }
    
    internal let impl: K1.PrivateKey
    internal let publicKeyImpl: K1.PublicKey
    
    public typealias PublicKey = PublicKeyOf<K1.KeyAgreement>
    public var publicKey: PublicKey {
        .init(impl: publicKeyImpl)
    }
    
    public init(impl: K1.PrivateKey) {
        self.impl = impl
        self.publicKeyImpl = impl.publicKey
    }
}
