//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension Bridge {
    public enum Scnhorr {}
}

extension Bridge.Scnhorr {
    public final class Wrapped: @unchecked Sendable, Hashable {
        public static let byteCount = 2 * Curve.Field.byteCount
        internal let bytes: [UInt8]
        
        public static func == (lhs: Wrapped, rhs: Wrapped) -> Bool {
            lhs.bytes == rhs.bytes
        }
        
        public func hash(into hasher: inout Hasher) {
            hasher.combine(bytes)
        }
        
        public var rawRepresentation: Data {
            Data(bytes)
        }
        
        
        public init(bytes: [UInt8]) throws {
            guard bytes.count == Self.byteCount else {
                throw Bridge.Error.failedToInitSchnorrSignatureInvalidByteCount(got: bytes.count, expected: Self.byteCount)
            }
            self.bytes = bytes
        }
    }
    public static func der(wrapped: Wrapped) -> [UInt8] {
        fatalError()
    }
    
    
}
