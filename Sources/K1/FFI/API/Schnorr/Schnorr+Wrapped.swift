//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation

extension FFI.Scnhorr {
    final class Wrapped: @unchecked Sendable, Hashable {
        static let byteCount = 2 * Curve.Field.byteCount
        
        internal let bytes: [UInt8]
        
        init(bytes: [UInt8]) throws {
            guard bytes.count == Self.byteCount else {
                throw K1.Error.failedToInitSchnorrSignatureInvalidByteCount(
                    got: bytes.count,
                    expected: Self.byteCount
                )
            }
            self.bytes = bytes
        }
    }
}

// MARK: Serialization
extension FFI.Scnhorr.Wrapped {
    var rawRepresentation: Data {
        Data(bytes)
    }
}

// MARK: Equatable
extension FFI.Scnhorr.Wrapped {
    static func == (lhs: FFI.Scnhorr.Wrapped, rhs: FFI.Scnhorr.Wrapped) -> Bool {
        lhs.bytes == rhs.bytes
    }
}

// MARK: Hashable
extension FFI.Scnhorr.Wrapped {
    func hash(into hasher: inout Hasher) {
        hasher.combine(bytes)
    }
}
