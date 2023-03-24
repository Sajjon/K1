//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-24.
//

import Foundation
import struct CryptoKit.SharedSecret

public struct PublicKeyOf<Feature>: Sendable, Hashable, K1PublicKeyProtocol {
    
    public init(rawRepresentation: some ContiguousBytes) throws {
        try self.init(impl: .init(rawRepresentation: rawRepresentation))
    }
    
    public init(compressedRepresentation: some ContiguousBytes) throws {
        try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
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
    
    public var compressedRepresentation: Data {
        impl.compressedRepresentation
    }
    
    public var pemRepresentation: String {
        impl.pemRepresentation
    }
    
    internal let impl: K1.PublicKey
    public init(impl: K1.PublicKey) {
        self.impl = impl
    }
}


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

extension K1 {
    public enum KeyAgreement {
        public typealias PrivateKey = PrivateKeyOf<Self>
        public typealias PublicKey = PrivateKey.PublicKey
    }
}

extension K1.KeyAgreement.PrivateKey {
    /// Computes a shared secret with the provided public key from another party,
    /// returning only the `X` coordinate of the point, following [ANSI X9.63][ansix963] standards.
    ///
    /// This is one of three ECDH functions, this library vendors, all three versions
    /// uses different serialization of the shared EC Point, specifically:
    /// 1. `ASN1 x9.63`: No hash, return only the `X` coordinate of the point <- this function
    /// 2. `libsecp256k1`: SHA-256 hash the compressed point
    /// 3. Custom: No hash, return point uncompressed
    ///
    /// This function uses 3. i.e. no hash, and returns only the `X` coordinate of the point.
    /// This is following the [ANSI X9.63][ansix963] standard serialization of the shared point.
    ///
    /// Further more this function is compatible with CryptoKit, since it returns a CryptoKit
    /// `SharedSecret` struct, thus offering you to use all of CryptoKit's Key Derivation Functions
    /// (`KDF`s), which can be called on the `SharedSecret`.
    ///
    /// As seen on [StackExchange][cryptostackexchange], this version is compatible with the following
    /// libraries:
    /// - JS: `elliptic` (v6.4.0 in nodeJS v8.2.1)
    /// - JS: `crypto` (builtin) - uses openssl under the hood (in nodeJS v8.2.1)
    /// - .NET: `BouncyCastle` (BC v1.8.1.3, .NET v2.1.4)
    /// - Python: pyca/cryptography (hazmat)
    ///
    /// [ansix963]: https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
    /// [cryptostackexchange]: https://crypto.stackexchange.com/a/57727
    public func sharedSecretFromKeyAgreement(
        with publicKey: PublicKey
    ) throws -> SharedSecret {
        let data = try FFI.ECDH.keyExchange(
            publicKey: publicKey.impl.wrapped,
            privateKey: self.impl.wrapped,
            serializeOutputFunction: .ansiX963
        )
        return try SharedSecret(data: data)
    }
    
    
    /// Computes a shared secret with the provided public key from another party,
    /// using `libsecp256k1` default behaviour, returning a hashed of the compressed point.
    ///
    /// This is one of three ECDH functions, this library vendors, all three versions
    /// uses different serialization of the shared EC Point, specifically:
    /// 1. `ASN1 x9.63`: No hash, return only the `X` coordinate of the point
    /// 2. `libsecp256k1`: SHA-256 hash the compressed point <- this function
    /// 3. Custom: No hash, return point uncompressed
    ///
    /// This function uses 1. i.e.SHA-256 hash the compressed point.
    /// This is using the [default behaviour of `libsecp256k1`][libsecp256k1], which does not adhere to any
    /// other standard.
    ///
    /// As seen on [StackExchange][cryptostackexchange], this version is compatible with all
    /// libraries which wraps `libsecp256k1`, e.g.:
    /// - Python wrapper: secp256k1 (v0.13.2, for python 3.6.4)
    /// - JS wrapper: secp256k1 (v3.5.0, for nodeJS v8.2.1)
    ///
    /// [libsecp256k1]: https://github.com/bitcoin-core/secp256k1/blob/master/src/modules/ecdh/main_impl.h#L27
    /// [cryptostackexchange]: https://crypto.stackexchange.com/a/57727
    ///
    public func ecdh(
        with publicKey: PublicKey,
        arbitraryData: Data? = nil
    ) throws -> SharedSecret {
        let data = try FFI.ECDH.keyExchange(
            publicKey: publicKey.impl.wrapped,
            privateKey: self.impl.wrapped,
            serializeOutputFunction: .libsecp256kDefault(arbitraryData: arbitraryData)
        )
        return try SharedSecret(data: data)
    }
    
    /// Computes a shared secret with the provided public key from another party,
    /// returning an uncompressed public point, unhashed.
    ///
    /// This is one of three ECDH functions, this library vendors, all three versions
    /// uses different serialization of the shared EC Point, specifically:
    /// 1. `ASN1 x9.63`: No hash, return only the `X` coordinate of the point
    /// 2. `libsecp256k1`: SHA-256 hash the compressed point
    /// 3. Custom: No hash, return point uncompressed <- this function
    ///
    /// This function uses 2. i.e. no hash, return point uncompressed
    /// **This is not following any standard at all**, but might be useful if you want to write your
    /// cryptographic functions, e.g. some ECIES scheme.
    ///
    public func ecdhPoint(with publicKey: PublicKey) throws -> Data {
        try FFI.ECDH.keyExchange(
            publicKey: publicKey.impl.wrapped,
            privateKey: self.impl.wrapped,
            serializeOutputFunction: .noHashWholePoint
        )
    }
}
