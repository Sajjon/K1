// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// MARK: Verify + ECDSA.NonRecoverable
extension K1.ECDSA.NonRecoverable.PublicKey {
	/// Verifies an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature to check against the _hashed_ data.
	///   - hashed: The _hashed_ data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature is valid for the given _hashed_ data.
	public func isValidSignature(
		_ signature: K1.ECDSA.NonRecoverable.Signature,
		hashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		do {
			return try FFI.ECDSA.NonRecoverable.isValid(
				signature: signature.wrapped,
				publicKey: self.impl.wrapped,
				message: [UInt8](hashed),
				options: options
			)
		} catch {
			return false
		}
	}

	/// Verifies an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature is valid for the given digest.
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

	/// Verifies an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`.
	///
	/// - Parameters:
	///   - signature: The an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature to check against the given digest.
	///   - unhashed: The block of data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the an Elliptic Curve Digital Signature Algorithm (ECDSA) non recoverable signature is valid for the given block of data.
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

// MARK: Verify + ECDSA.Recoverable
extension K1.ECDSA.Recoverable.PublicKey {
	/// Verifies an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature to check against the _hashed_ data.
	///   - hashed: The _hashed_ data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature is valid for the given _hashed_ data.
	public func isValidSignature(
		_ signature: K1.ECDSA.Recoverable.Signature,
		hashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		do {
			return try FFI.ECDSA.Recoverable.isValid(
				signature: signature.wrapped,
				publicKey: self.impl.wrapped,
				message: [UInt8](hashed),
				options: options
			)
		} catch {
			return false
		}
	}

	/// Verifies an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature is valid for the given digest.
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

	/// Verifies an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`.
	///
	/// - Parameters:
	///   - signature: The an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature to check against the given digest.
	///   - unhashed: The block of data covered by the signature.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: A Boolean value that’s true if the an Elliptic Curve Digital Signature Algorithm (ECDSA) recoverable signature is valid for the given block of data.
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

// MARK: Verify + Schnorr
extension K1.Schnorr.PublicKey {
	/// Verifies Schnorr signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The Schnorr signature to check against the _hashed_ data.
	///   - hashed: The _hashed_ data covered by the signature.
	/// - Returns: A Boolean value that’s true if the Schnorr signature is valid for the given _hashed_ data.
	public func isValidSignature(
		_ signature: K1.Schnorr.Signature,
		hashed: some DataProtocol
	) -> Bool {
		do {
			return try FFI.Schnorr.isValid(
				signature: signature.wrapped,
				publicKey: self.impl.wrapped,
				message: [UInt8](hashed)
			)
		} catch {
			return false
		}
	}

	/// Verifies Schnorr signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The Schnorr signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	/// - Returns: A Boolean value that’s true if the Schnorr signature is valid for the given digest.
	public func isValidSignature(
		_ signature: K1.Schnorr.Signature,
		digest: some Digest
	) -> Bool {
		isValidSignature(
			signature,
			hashed: Data(digest)
		)
	}

	/// Verifies Schnorr signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`.
	///
	/// - Parameters:
	///   - signature: The Schnorr signature to check against the given digest.
	///   - unhashed: The block of data covered by the signature.
	/// - Returns: A Boolean value that’s true if the Schnorr signature is valid for the given block of data.
	public func isValidSignature(
		_ signature: K1.Schnorr.Signature,
		unhashed: some DataProtocol
	) -> Bool {
		isValidSignature(
			signature,
			digest: SHA256.hash(data: unhashed)
		)
	}
}
