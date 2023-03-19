//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//


import Foundation
import FFI


public struct SchnorrSignature: Sendable, Hashable {
    
    typealias Wrapped = Bridge.Scnhorr.Wrapped
    internal let wrapped: Wrapped
    internal init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
    
    public var rawRepresentation: Data {
        wrapped.rawRepresentation
    }
    
    public init(rawRepresentation: some DataProtocol) throws {
        try self.init(wrapped: .init(bytes: [UInt8](rawRepresentation)))
    }
}

public extension SchnorrSignature {
    
    func compactRepresentation() throws -> Data {
        // FIXME: Needed?
//        try Bridge.compactRepresentationOfSignature(rawRepresentation: rawRepresentation)
        fatalError()
    }
    func derRepresentation() throws -> Data {
        // FIXME: Needed?
//        try Bridge.derRepresentationOfSignature(rawRepresentation: rawRepresentation)
//        Data(Bridge.Scnhorr.der(wrapped: .init())
        fatalError()
    }
    
  
    
}
