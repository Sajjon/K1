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
    
    /// `04 || X || Y` 65 bytes
    public init(x963Representation: some ContiguousBytes) throws {
        try self.init(wrapped: FFI.PublicKey.from(x963Representation: x963Representation))
    }
    
    /// `DER`
    public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
        let bytes = [UInt8](derRepresentation)
        let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
        self = try .init(x963Representation: parsed.key)
    }
    
    /// `X || Y` as 64 bytes
    public init(compactRepresentation: some ContiguousBytes) throws {
        try self.init(wrapped: FFI.PublicKey.from(compactRepresentation: compactRepresentation))
    }
    
    /// `02|03 || X` as 33 bytes
    public init(compressedRepresentation: some ContiguousBytes) throws {
        try self.init(wrapped: FFI.PublicKey.from(compressedRepresentation: compressedRepresentation))
    }
}

// MARK: Serialize
extension K1.PublicKey {
    
    /// `04 || X || Y` 65 bytes
    public var x963Representation: Data {
        try! FFI.PublicKey.rawRepresentation(wrapped, format: .uncompressed)
    }
    
    /// `02|03 || X` as 33 bytes
    public var compressedRepresentation: Data {
        try! FFI.PublicKey.rawRepresentation(wrapped, format: .compressed)
    }
    
    public var derRepresentation: Data {
        let spki = ASN1.SubjectPublicKeyInfo(
            algorithmIdentifier: .secp256k1,
            key: Array(self.x963Representation)
        )
        var serializer = ASN1.Serializer()
        
        // Serializing these keys can't throw
        try! serializer.serialize(spki)
        return Data(serializer.serializedBytes)
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
