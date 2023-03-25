//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

public protocol K1PublicKeyProtocol: K1KeyPortable {
    init(compressedRepresentation: some ContiguousBytes) throws
    var compressedRepresentation: Data { get }
}

extension K1 {
    
    struct _PublicKeyImplementation: Sendable, Hashable, K1PublicKeyProtocol {
        
        typealias Wrapped = FFI.PublicKey.Wrapped
        internal let wrapped: Wrapped
        
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
    }
}

// MARK: Init
extension K1._PublicKeyImplementation {
    

    /// `04 || X || Y` (65 bytes)
    static let x963ByteCount = FFI.PublicKey.x963ByteCount
    
    /// `X || Y` (64 bytes)
    static let rawByteCount = FFI.PublicKey.rawByteCount

    /// `02|03 || X` (33 bytes)
    static let compressedByteCount = FFI.PublicKey.compressedByteCount
    
    /// `X || Y` (64 bytes)
    init(rawRepresentation: some ContiguousBytes) throws {
        try self.init(
            wrapped: FFI.PublicKey.deserialize(rawRepresentation: rawRepresentation)
        )
    }
    
    /// `04 || X || Y` (65 bytes)
    init(x963Representation: some ContiguousBytes) throws {
        try self.init(
            wrapped: FFI.PublicKey.deserialize(x963Representation: x963Representation)
        )
    }
    
    /// `DER`
    init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
        let bytes = [UInt8](derRepresentation)
        let parsed = try ASN1.SubjectPublicKeyInfo(asn1Encoded: bytes)
        self = try .init(x963Representation: parsed.key)
    }
    
    /// `02|03 || X` (33 bytes)
    init(compressedRepresentation: some ContiguousBytes) throws {
        try self.init(
            wrapped: FFI.PublicKey.deserialize(compressedRepresentation: compressedRepresentation)
        )
    }

    /// Creates a `secp256k1` key from a Privacy-Enhanced Mail (PEM) representation.
    init(pemRepresentation: String) throws {
        let pem = try ASN1.PEMDocument(pemString: pemRepresentation)
        guard pem.type == Self.pemType else {
            throw K1.Error.invalidPEMDocument
        }
        self = try .init(derRepresentation: pem.derBytes)
    }

}

extension K1._PublicKeyImplementation {
    static let pemType = "PUBLIC KEY"
}

// MARK: Serialize
extension K1._PublicKeyImplementation {
    
    /// `X || Y` (64 bytes)
    var rawRepresentation: Data {
        Data(x963Representation.dropFirst())
    }
    
    
    /// `04 || X || Y` (65 bytes)
    var x963Representation: Data {
        try! FFI.PublicKey.serialize(wrapped, format: .uncompressed)
    }
    
    /// `02|03 || X` (33 bytes)
    var compressedRepresentation: Data {
        try! FFI.PublicKey.serialize(wrapped, format: .compressed)
    }
    
    /// `DER`
    var derRepresentation: Data {
        let spki = ASN1.SubjectPublicKeyInfo(
            algorithmIdentifier: .secp256k1,
            key: Array(self.x963Representation)
        )
        var serializer = ASN1.Serializer()
        
        // Serializing these keys can't throw
        try! serializer.serialize(spki)
        return Data(serializer.serializedBytes)
    }
    
    /// A Privacy-Enhanced Mail (PEM) representation of the public key.
    public var pemRepresentation: String {
        let pemDocument = ASN1.PEMDocument(type: Self.pemType, derBytes: self.derRepresentation)
        return pemDocument.pemString
    }
}

// MARK: Equatable
extension K1._PublicKeyImplementation {
    static func == (lhsSelf: Self, rhsSelf: Self) -> Bool {
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
extension K1._PublicKeyImplementation {
    func hash(into hasher: inout Hasher) {
        wrapped.withUnsafeBytes {
            hasher.combine(bytes: $0)
        }
    }
}
