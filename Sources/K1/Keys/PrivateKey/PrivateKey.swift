//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

@_spi(Internals) import FFI
import CryptoKit
import Foundation

// MARK: - PrivateKey
public extension K1 {
    
    struct PrivateKey: Sendable, Hashable {
        
        typealias Wrapped = Bridge.PrivateKey.Wrapped
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
        try self.init(wrapped: Bridge.PrivateKey.from(rawRepresentation: rawRepresentation))
    }
    
    public init() {
        self.init(wrapped: .init())
    }
}


// MARK: - Equatable
public extension K1.PrivateKey {
    /// Two PrivateKey are considered equal if their PublicKeys are equal
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.publicKey == rhs.publicKey
    }
}

// MARK: - Hashable
public extension K1.PrivateKey {
    /// We use the public key of the private key as input to hash
    func hash(into hasher: inout Hasher) {
        hasher.combine(self.publicKey)
    }
}

// MARK: Schnorr Sign
extension K1.PrivateKey {
    
    public func schnorrSign(
        hashed: some DataProtocol,
        input: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        let wrapped = try Bridge.Scnhorr.sign(
            hashedMessage: [UInt8](hashed),
            privateKey: wrapped,
            input: input
        )
        return SchnorrSignature(
            wrapped: wrapped
        )
    }
    
    public func schnorrSign(
        digest: some Digest,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try schnorrSign(hashed: Array(digest), input: maybeInput)
    }
    
}

// MARK: ECDSA Non-Recoverable
extension K1.PrivateKey {
    public func ecdsaSignNonRecoverable(
        digest: some Digest,
        mode: Bridge.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        try ECDSASignatureNonRecoverable(
            wrapped: Bridge.ECDSA.NonRecovery.sign(
                hashedMessage: [UInt8](digest),
                privateKey: wrapped,
                mode: mode
            )
        )
    }
    
    /// SHA256 hashes `unhashed` before signing it.
    public func ecdsaSignNonRecoverable(
        unhashed: some DataProtocol,
        mode: Bridge.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        try ecdsaSignNonRecoverable(digest: SHA256.hash(data: unhashed), mode: mode)
    }
}

// MARK: ECDSA Recoverable
extension K1.PrivateKey {
    public func ecdsaSignRecoverable(
        digest: some Digest,
        mode: Bridge.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ECDSASignatureRecoverable(
            wrapped: Bridge.ECDSA.Recovery.sign(
                hashedMessage: [UInt8](digest),
                privateKey: wrapped,
                mode: mode
            )
        )
    }
    
    public func ecdsaSignRecoverable<D: DataProtocol>(
        unhashed data: D,
        mode: Bridge.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ecdsaSignRecoverable(digest: SHA256.hash(data: data), mode: mode)
    }
}

// MARK: ECDH
extension K1.PrivateKey {
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
        with publicKey: K1.PublicKey
    ) throws -> SharedSecret {
        let data = try Bridge.ECDH.keyExchange(
            publicKey: publicKey.wrapped,
            privateKey: self.wrapped,
            serializeOutputFunction: .ansiX963
        )
        return try SharedSecret.init(data: data)
        
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
        with publicKey: K1.PublicKey,
        arbitraryData: Data? = nil
    ) throws -> SharedSecret {
        let data = try Bridge.ECDH.keyExchange(
            publicKey: publicKey.wrapped,
            privateKey: self.wrapped,
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
    public func ecdhPoint(with publicKey: K1.PublicKey) throws -> Data {
        try Bridge.ECDH.keyExchange(
            publicKey: publicKey.wrapped,
            privateKey: self.wrapped,
            serializeOutputFunction: .noHashWholePoint
        )
    }
    
}



