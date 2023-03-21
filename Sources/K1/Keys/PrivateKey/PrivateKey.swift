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
    
   
    public init(
        rawRepresentation: some DataProtocol
    ) throws {
        try self.init(
            wrapped: FFI.PrivateKey.deserialize(rawRepresentation: rawRepresentation)
        )
    }
    
    public init() {
        self.init(wrapped: .init())
    }
}

// MARK: Serialize
extension K1.PrivateKey {

    /// A data representation of the private key.
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
        let pointByteCount = Curve.Field.byteCount
        var bytes = Data()
        bytes.reserveCapacity(Self.x963ByteCount)
        bytes.append(contentsOf: publicKey.x963Representation)
        bytes.append(self.rawRepresentation)
        return bytes
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
