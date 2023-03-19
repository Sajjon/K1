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
}

// MARK: Init
extension SchnorrSignature {
    public init(rawRepresentation: some DataProtocol) throws {
        try self.init(wrapped: .init(bytes: [UInt8](rawRepresentation)))
    }
}

// MARK: Serialize
extension SchnorrSignature {
    public var rawRepresentation: Data {
        wrapped.rawRepresentation
    }
}
