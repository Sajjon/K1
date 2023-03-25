import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

extension K1 {
	/// A mechanism used to create or verify a cryptographic signature using the `secp256k1` and Schnorr signature scheme.
	public enum Schnorr: K1Feature {
		/// A `secp256k1` private key used to create cryptographic signatures,
		/// more specifically Schnorr signatures.
		public typealias PrivateKey = PrivateKeyOf<Self>

		/// A `secp256k1` public key used to verify cryptographic signatures,
		/// more specifically Schnorr signatures.
		public typealias PublicKey = PublicKeyOf<Self>
	}
}

// MARK: Sign
extension K1.Schnorr.PrivateKey {
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

	public func signature(
		for digest: some Digest,
		options: K1.Schnorr.SigningOptions = .default
	) throws -> K1.Schnorr.Signature {
		try signature(
			for: [UInt8](digest),
			options: options
		)
	}

	/// SHA256 hashes `unhashed` before signing it.
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

// MARK: Validate
extension K1.Schnorr.PublicKey {
	/// Verifies a Schnorr signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The Schnorr signature to check against the _hashed_ data.
	///   - hashed: The _hashed_ data covered by the signature.
	/// - Returns: A Boolean value that’s true if the signature is valid for the given _hashed_ data.
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

	/// Verifies a Schnorr signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The Schnorr signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	/// - Returns: A Boolean value that’s true if the signature is valid for the given digest.
	public func isValidSignature(
		_ signature: K1.Schnorr.Signature,
		digest: some Digest
	) -> Bool {
		isValidSignature(
			signature,
			hashed: [UInt8](digest)
		)
	}

	/// Verifies a Schnorr signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`
	/// .
	/// - Parameters:
	///   - signature: The Schnorr signature to check against the block of data.
	///   - unhashed: The block of data covered by the signature.
	/// - Returns: A Boolean value that’s true if the signature is valid for the given block of data.
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

extension K1.Schnorr {
	public struct SigningOptions: Sendable, Hashable {
		public let auxilaryRandomData: AuxilaryRandomData?
		public init(auxilaryRandomData: AuxilaryRandomData? = nil) {
			self.auxilaryRandomData = auxilaryRandomData
		}
	}
}

extension K1.Schnorr.SigningOptions {
	public static let `default` = Self()

	public struct AuxilaryRandomData: Sendable, Hashable {
		public let aux: [UInt8]

		public init(aux: some DataProtocol) throws {
			guard aux.count == Curve.Field.byteCount else {
				throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
			}
			self.aux = [UInt8](aux)
		}
	}
}
