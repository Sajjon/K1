//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//


import Foundation
import FFI


public struct SchnorrSignature: Sendable, Hashable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.withUnsafeBytes { lhsBytes in
            rhs.wrapped.withUnsafeBytes { rhsBytes in
                safeCompare(lhsBytes, rhsBytes)
            }
        }
    }
    public func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
    
    
//    private let _rawRepresentation: [UInt8]
    
    typealias Wrapped = Bridge.Scnhorr.Wrapped
    internal let wrapped: Wrapped
    internal init(wrapped: Wrapped) {
        self.wrapped = wrapped
    }
    
    public var rawRepresentation: Data {
       fatalError()
    }
    
    public init(rawRepresentation: some DataProtocol) throws {
        try self.init(wrapped: .init(bytes: [UInt8](rawRepresentation)))
    }
}

public extension SchnorrSignature {
    
    func compactRepresentation() throws -> Data {
        try Bridge.compactRepresentationOfSignature(rawRepresentation: rawRepresentation)
    }
    func derRepresentation() throws -> Data {
//        try Bridge.derRepresentationOfSignature(rawRepresentation: rawRepresentation)
//        Data(Bridge.Scnhorr.der(wrapped: .init())
        fatalError()
    }
    
  
    
}
