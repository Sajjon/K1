// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// swiftlint:disable all

// MARK: Sign + ECDSA
extension K1.ECDSA.PrivateKey {
	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - hashed: The _hashed_ data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for hashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Signature {
		try K1.ECDSA.Signature(
			wrapped: FFI.ECDSA.sign(
				hashedMessage: [UInt8](hashed),
				privateKey: impl.wrapped,
				options: options
			)
		)
	}

	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature of the digest you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - digest: The digest of the data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for digest: some Digest,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Signature {
		try signature(
			for: Data(digest),
			options: options
		)
	}

	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
	/// - Parameters:
	///   - unhashed: The data hash and then to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		forUnhashed unhashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Signature {
		try signature(
			for: SHA256.hash(data: unhashed),
			options: options
		)
	}
}

// MARK: Sign + ECDSAWithKeyRecovery
extension K1.ECDSAWithKeyRecovery.PrivateKey {
	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - hashed: The _hashed_ data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for hashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSAWithKeyRecovery.Signature {
		try K1.ECDSAWithKeyRecovery.Signature(
			wrapped: FFI.ECDSAWithKeyRecovery.sign(
				hashedMessage: [UInt8](hashed),
				privateKey: impl.wrapped,
				options: options
			)
		)
	}

	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature of the digest you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - digest: The digest of the data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for digest: some Digest,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSAWithKeyRecovery.Signature {
		try signature(
			for: Data(digest),
			options: options
		)
	}

	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
	/// - Parameters:
	///   - unhashed: The data hash and then to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		forUnhashed unhashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSAWithKeyRecovery.Signature {
		try signature(
			for: SHA256.hash(data: unhashed),
			options: options
		)
	}
}

// MARK: Sign + Schnorr
extension K1.Schnorr.PrivateKey {
	/// Generates Schnorr signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - hashed: The _hashed_ data to sign.
	///   - options: Optional auxiliary random data to use when forming nonce for the signature.
	/// - Returns: The Schnorr signature corresponding to the data.
	public func signature(
		for hashed: some DataProtocol,
		options: K1.Schnorr.SigningOptions = .default
	) throws -> K1.Schnorr.Signature {
		try K1.Schnorr.Signature(
			wrapped: FFI.Schnorr.sign(
				hashedMessage: [UInt8](hashed),
				privateKey: impl.wrapped,
				options: options
			)
		)
	}

	/// Generates Schnorr signature of the digest you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - digest: The digest of the data to sign.
	///   - options: Optional auxiliary random data to use when forming nonce for the signature.
	/// - Returns: The Schnorr signature corresponding to the data.
	public func signature(
		for digest: some Digest,
		options: K1.Schnorr.SigningOptions = .default
	) throws -> K1.Schnorr.Signature {
		try signature(
			for: Data(digest),
			options: options
		)
	}

	/// Generates Schnorr signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
	/// - Parameters:
	///   - unhashed: The data hash and then to sign.
	///   - options: Optional auxiliary random data to use when forming nonce for the signature.
	/// - Returns: The Schnorr signature corresponding to the data.
	public func signature(
		forUnhashed unhashed: some DataProtocol,
		options: K1.Schnorr.SigningOptions = .default
	) throws -> K1.Schnorr.Signature {
		try signature(
			for: SHA256.hash(data: unhashed),
			options: options
		)
	}
}

// swiftlint:enable all
