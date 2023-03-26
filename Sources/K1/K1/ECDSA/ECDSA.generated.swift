// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// MARK: - K1.ECDSA
extension K1 {
	/// A mechanism used to create or verify a cryptographic signature using the `secp256k1` elliptic curve digital signature algorithm (ECDSA).
	public enum ECDSA {}
}

// MARK: - K1.ECDSA.ValidationOptions
extension K1.ECDSA {
	public struct ValidationOptions {
		public let malleabilityStrictness: MalleabilityStrictness

		public init(malleabilityStrictness: MalleabilityStrictness) {
			self.malleabilityStrictness = malleabilityStrictness
		}
	}
}

extension K1.ECDSA.ValidationOptions {
	public static let `default`: Self = .init(
		malleabilityStrictness: .rejected
	)

	/// Whether or not to consider malleable signatures valid.
	///
	/// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
	public enum MalleabilityStrictness {
		/// Considers all malleable signatures **invalid**.
		case rejected

		/// Accepts malleable signatures valid.
		case accepted
	}
}

// MARK: - K1.ECDSA.SigningOptions
extension K1.ECDSA {
	public struct SigningOptions: Sendable, Hashable {
		public let nonceFunction: NonceFunction

		public init(nonceFunction: NonceFunction) {
			self.nonceFunction = nonceFunction
		}
	}
}

extension K1.ECDSA.SigningOptions {
	public static let `default`: Self = .init(nonceFunction: .deterministic())

	public enum NonceFunction: Sendable, Hashable {
		case random

		/// RFC6979
		case deterministic(arbitraryData: RFC6979ArbitraryData? = nil)
	}
}

// MARK: - K1.ECDSA.SigningOptions.NonceFunction.RFC6979ArbitraryData
extension K1.ECDSA.SigningOptions.NonceFunction {
	public struct RFC6979ArbitraryData: Sendable, Hashable {
		public let arbitraryData: [UInt8]
		public init(arbitraryData: [UInt8]) throws {
			guard arbitraryData.count == Curve.Field.byteCount else {
				throw K1.Error.incorrectByteCountOfArbitraryDataForNonceFunction
			}
			self.arbitraryData = arbitraryData
		}
	}
}

// MARK: Sign + ECDSA.NonRecoverable
extension K1.ECDSA.NonRecoverable.PrivateKey {
	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - hashed: The _hashed_ data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The non recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for hashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.NonRecoverable.Signature {
		try K1.ECDSA.NonRecoverable.Signature(
			wrapped: FFI.ECDSA.NonRecoverable.sign(
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
	/// - Returns: The non recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for digest: some Digest,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.NonRecoverable.Signature {
		try signature(
			for: Data(digest),
			options: options
		)
	}

	/// Generates an elliptic curve digital signature algorithm (ECDSA) non recoverable signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
	/// - Parameters:
	///   - unhashed: The data hash and then to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The non recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		forUnhashed unhashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.NonRecoverable.Signature {
		try signature(
			for: SHA256.hash(data: unhashed),
			options: options
		)
	}
}

// MARK: Verify + ECDSA.NonRecoverable
extension K1.ECDSA.NonRecoverable.PublicKey {
	/// Verifies an elliptic curve digital signature algorithm (ECDSA) non recoverable signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The non recoverable signature to check against the _hashed_ data.
	///   - hashed: The _hashed_ data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the non recoverable signature is valid for the given _hashed_ data.
	public func isValidSignature(
		_ signature: K1.ECDSA.NonRecoverable.Signature,
		hashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		do {
			return try FFI.ECDSA.NonRecoverable.isValid(
				ecdsaSignature: signature.wrapped,
				publicKey: self.impl.wrapped,
				message: [UInt8](hashed),
				options: options
			)
		} catch {
			return false
		}
	}

	/// Verifies an elliptic curve digital signature algorithm (ECDSA) non recoverable signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The non recoverable signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the non recoverable signature is valid for the given digest.
	public func isValidSignature(
		_ signature: K1.ECDSA.NonRecoverable.Signature,
		digest: some Digest,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		isValidSignature(
			signature,
			hashed: Data(digest),
			options: options
		)
	}

	/// Verifies an elliptic curve digital signature algorithm (ECDSA) non recoverable signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`.
	///
	/// - Parameters:
	///   - signature: The non recoverable signature to check against the given digest.
	///   - unhashed: The block of data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the non recoverable signature is valid for the given block of data.
	public func isValidSignature(
		_ signature: K1.ECDSA.NonRecoverable.Signature,
		unhashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		isValidSignature(
			signature,
			digest: SHA256.hash(data: unhashed),
			options: options
		)
	}
}

// MARK: Sign + ECDSA.Recoverable
extension K1.ECDSA.Recoverable.PrivateKey {
	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - hashed: The _hashed_ data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for hashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Recoverable.Signature {
		try K1.ECDSA.Recoverable.Signature(
			wrapped: FFI.ECDSA.Recoverable.sign(
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
	/// - Returns: The recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for digest: some Digest,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Recoverable.Signature {
		try signature(
			for: Data(digest),
			options: options
		)
	}

	/// Generates an elliptic curve digital signature algorithm (ECDSA) recoverable signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
	/// - Parameters:
	///   - unhashed: The data hash and then to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The recoverable signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		forUnhashed unhashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Recoverable.Signature {
		try signature(
			for: SHA256.hash(data: unhashed),
			options: options
		)
	}
}

// MARK: Verify + ECDSA.Recoverable
extension K1.ECDSA.Recoverable.PublicKey {
	/// Verifies an elliptic curve digital signature algorithm (ECDSA) recoverable signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The recoverable signature to check against the _hashed_ data.
	///   - hashed: The _hashed_ data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the recoverable signature is valid for the given _hashed_ data.
	public func isValidSignature(
		_ signature: K1.ECDSA.Recoverable.Signature,
		hashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		do {
			return try FFI.ECDSA.Recoverable.isValid(
				ecdsaSignature: signature.wrapped,
				publicKey: self.impl.wrapped,
				message: [UInt8](hashed),
				options: options
			)
		} catch {
			return false
		}
	}

	/// Verifies an elliptic curve digital signature algorithm (ECDSA) recoverable signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The recoverable signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the recoverable signature is valid for the given digest.
	public func isValidSignature(
		_ signature: K1.ECDSA.Recoverable.Signature,
		digest: some Digest,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		isValidSignature(
			signature,
			hashed: Data(digest),
			options: options
		)
	}

	/// Verifies an elliptic curve digital signature algorithm (ECDSA) recoverable signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`.
	///
	/// - Parameters:
	///   - signature: The recoverable signature to check against the given digest.
	///   - unhashed: The block of data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the recoverable signature is valid for the given block of data.
	public func isValidSignature(
		_ signature: K1.ECDSA.Recoverable.Signature,
		unhashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		isValidSignature(
			signature,
			digest: SHA256.hash(data: unhashed),
			options: options
		)
	}
}
