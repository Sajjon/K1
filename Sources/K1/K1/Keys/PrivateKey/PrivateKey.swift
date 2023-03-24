//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import CryptoKit
import Foundation

// MARK: - PrivateKey
extension K1 {
    
    public struct PrivateKey: Sendable, Hashable {
        
        typealias Wrapped = FFI.PrivateKey.Wrapped
        internal let wrapped: Wrapped
        
        public let publicKey: PublicKey
        
        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
            self.publicKey = PublicKey(wrapped: wrapped.publicKey)
        }
    }
}

// MARK: Inits
extension K1.PrivateKey {
    
    /// Creates a `secp256k1` private key from a Privacy-Enhanced Mail (PEM) representation.
    public init(
        pemRepresentation: String
    ) throws {
        let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

        switch pem.type {
        case "EC PRIVATE KEY":
            let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
            self = try .init(rawRepresentation: parsed.privateKey)
        case "PRIVATE KEY":
            let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
            self = try .init(rawRepresentation: parsed.privateKey.privateKey)
        default:
            throw K1.Error.invalidPEMDocument
        }
    }
   
    public init(
        rawRepresentation: some ContiguousBytes
    ) throws {
        try self.init(
            wrapped: FFI.PrivateKey.deserialize(rawRepresentation: rawRepresentation)
        )
    }
    
    public init(
        x963Representation: some ContiguousBytes
    ) throws {
        let length = x963Representation.withUnsafeBytes { $0.count }
        guard length == Self.x963ByteCount else {
            throw K1.Error.incorrectByteCountOfX963PrivateKey(got: length, expected: Self.x963ByteCount)
        }
        
        let publicKeyX963 = x963Representation.bytes.prefix(K1.PublicKey.x963ByteCount)
        let publicKeyFromX963 = try K1.PublicKey.init(x963Representation: publicKeyX963)
        let privateKeyRaw = x963Representation.bytes.suffix(Self.rawByteCount)
        try self.init(rawRepresentation: privateKeyRaw)
        guard self.publicKey == publicKeyFromX963 else {
            throw K1.Error.invalidPrivateX963RepresentationPublicKeyDiscrepancy
        }
        // All good
    }
    
    
    /// `DER`
    public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
        let bytes = Array(derRepresentation)
        
        // We have to try to parse this twice because we have no informaton about what kind of key this is.
        // We try with PKCS#8 first, and then fall back to SEC.1.
        do {
            let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
            self = try .init(rawRepresentation: key.privateKey.privateKey)
        } catch {
            let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
            self = try .init(rawRepresentation: key.privateKey)
        }
    }
    
    public init() {
        self.init(wrapped: .init())
    }
}

// MARK: Serialize
extension K1.PrivateKey {

    /// A raw representation of the private key.
    public var rawRepresentation: Data {
        Data(wrapped.secureBytes.bytes)
    }
    
    /// A Distinguished Encoding Rules (DER) encoded representation of the private key.
    public var derRepresentation: Data {
        let pkey = ASN1.PKCS8PrivateKey(
            algorithm: .secp256k1,
            privateKey: Array(self.rawRepresentation),
            publicKey: Array(self.publicKey.x963Representation)
        )
        var serializer = ASN1.Serializer()

        // Serializing these keys can't throw
        try! serializer.serialize(pkey)
        return Data(serializer.serializedBytes)
    }

    /// A Privacy-Enhanced Mail (PEM) representation of the private key.
    public var pemRepresentation: String {
        let pemDocument = ASN1.PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
        return pemDocument.pemString
    }
    
    /// An ANSI x9.63 representation of the private key.
    public var x963Representation: Data {
        // The x9.63 private key format is a discriminator byte (0x4) concatenated with the X and Y points
        // of the public key, and the K value of the secret scalar. Let's load that in.
        var bytes = Data()
        bytes.reserveCapacity(Self.x963ByteCount)
        bytes.append(contentsOf: publicKey.x963Representation)
        bytes.append(self.rawRepresentation)
        return bytes
    }
    

    public static let rawByteCount = Curve.Field.byteCount
    public static let x963ByteCount = K1.PublicKey.x963ByteCount + K1.PrivateKey.rawByteCount
}


// MARK: - Equatable
extension K1.PrivateKey {
    /// Constant-time comparision.
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.wrapped.secureBytes == rhs.wrapped.secureBytes
    }
}

// MARK: - Hashable
extension K1.PrivateKey {
    /// We use the public key of the private key as input to hash
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.publicKey)
    }
}
