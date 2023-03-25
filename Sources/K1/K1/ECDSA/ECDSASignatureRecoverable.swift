import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

extension K1.ECDSA {
	/// A mechanism used to create or verify a cryptographic signature using the `secp256k1` elliptic curve digital signature algorithm (ECDSA), signatures that do offers recovery of the public key.
	public enum Recoverable: K1Feature {
		/// A `secp256k1` private key used to create cryptographic signatures,
		/// more specifically ECDSA signatures that offers recovery of the public key.
		public typealias PrivateKey = PrivateKeyOf<Self>

		/// A `secp256k1` public key used to verify cryptographic signatures.
		/// more specifically ECDSA signatures that offers recovery of the public key.
		public typealias PublicKey = PublicKeyOf<Self>
	}
}

// MARK: Sign
extension K1.ECDSA.Recoverable.PrivateKey {
	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of _hashed_ data you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - hashed: The _hashed_ data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for hashed: some DataProtocol,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Recoverable.Signature {
		try K1.ECDSA.Recoverable.Signature(
			wrapped: FFI.ECDSA.Recovery.sign(
				hashedMessage: [UInt8](hashed),
				privateKey: impl.wrapped,
				options: options
			)
		)
	}

	/// Generates an Elliptic Curve Digital Signature Algorithm (ECDSA) signature of the digest you provide over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - digest: The digest of the data to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
	public func signature(
		for digest: some Digest,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> K1.ECDSA.Recoverable.Signature {
		try signature(
			for: Data(digest),
			options: options
		)
	}

	/// Generates an elliptic curve digital signature algorithm (ECDSA) signature of the given data over the `secp256k1` elliptic curve, using SHA-256 as a hash function.
	/// - Parameters:
	///   - unhashed: The data hash and then to sign.
	///   - options: Whether or not to consider malleable signatures valid.
	/// - Returns: The signature corresponding to the data. The signing algorithm uses deterministic or random nonces, dependent on `options`, thus either deterministically producing the same signature or the same data and key, or different on every call.
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

// MARK: Validate
extension K1.ECDSA.Recoverable.PublicKey {
	/// Verifies a recoverable ECDSA signature on some _hash_ over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The recoverable ECDSA signature to check against the given digest.
	///   - hashed: The _hashed_ data covered by the signature.
	///   - options: ECDSA validation options used during validation
	/// - Returns: A Boolean value that’s true if the signature is valid for the given _hashed_ data.
	public func isValidSignature(
		_ signature: K1.ECDSA.Recoverable.Signature,
		hashed: some DataProtocol,
		options: K1.ECDSA.ValidationOptions = .default
	) -> Bool {
		do {
			let publicKeyNonRecoverable = try K1.ECDSA.NonRecoverable.PublicKey(rawRepresentation: self.rawRepresentation)
			let signatureNonRecoverable = try signature.nonRecoverable()

			return publicKeyNonRecoverable.isValidSignature(
				signatureNonRecoverable,
				hashed: hashed,
				options: options
			)
		} catch {
			return false
		}
	}

	/// Verifies a recoverable ECDSA signature on a digest over the `secp256k1` elliptic curve.
	/// - Parameters:
	///   - signature: The recoverable ECDSA signature to check against the given digest.
	///   - digest: The digest covered by the signature.
	///   - options: ECDSA validation options used during validation
	/// - Returns: A Boolean value that’s true if the signature is valid for the given digest.
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

	/// Verifies a recoverable ECDSA signature on a block of data over the `secp256k1` elliptic curve.
	///
	/// The function computes an SHA-256 hash from the data before verifying the signature. If you separately hash the data to be signed, use `isValidSignature(_:digest:input)` with the created digest. Or if you have access to a digest just as `some DataProtocol`, use
	/// `isValidSignature(_:hashed:input)`.
	///
	/// - Parameters:
	///   - signature: The recoverable ECDSA signature to check against the given digest.
	///   - unhashed: The block of data covered by the signature.
	///   - options: ECDSA validation options used during validation
	/// - Returns: A Boolean value that’s true if the signature is valid for the given block of data.
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

extension K1.ECDSA.Recoverable {
	public struct Signature: Sendable, Hashable, ContiguousBytes {
		typealias Wrapped = FFI.ECDSA.Recovery.Wrapped
		private let wrapped: Wrapped

		internal init(wrapped: Wrapped) {
			self.wrapped = wrapped
		}
	}
}

// MARK: Init
extension K1.ECDSA.Recoverable.Signature {
	/// Compact aka `IEEE P1363` aka `R||S`.
	public init(compact: Compact) throws {
		try self.init(
			wrapped: FFI.ECDSA.Recovery.deserialize(
				compact: [UInt8](compact.compact),
				recoveryID: compact.recoveryID.recid
			)
		)
	}

	/// Compact aka `IEEE P1363` aka `R||S`.
	public init(compact: Data, recoveryID: RecoveryID) throws {
		try self.init(compact: .init(compact: compact, recoveryID: recoveryID))
	}

	public init(
		rawRepresentation: some DataProtocol
	) throws {
		try self.init(
			wrapped: FFI.ECDSA.Recovery.deserialize(rawRepresentation: rawRepresentation)
		)
	}
}

// MARK: ContiguousBytes
extension K1.ECDSA.Recoverable.Signature {
	public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try wrapped.withUnsafeBytes(body)
	}
}

// MARK: Serialize
extension K1.ECDSA.Recoverable.Signature {
	internal var rawRepresentation: Data {
		Data(wrapped.bytes)
	}

	/// Compact aka `IEEE P1363` aka `R||S` with `RecoveryID`
	public func compact() throws -> Compact {
		let (rs, recid) = try FFI.ECDSA.Recovery.serializeCompact(
			wrapped
		)
		return try .init(
			compact: Data(rs),
			recoveryID: .init(recid: recid)
		)
	}

	public struct Compact: Sendable, Hashable {
		/// Compact aka `IEEE P1363` aka `R||S`.
		public let compact: Data

		public let recoveryID: RecoveryID

		/// Compact aka `IEEE P1363` aka `R||S`.
		public init(
			compact: Data,
			recoveryID: RecoveryID
		) throws {
			guard compact.count == Self.byteCountRS else {
				throw K1.Error.failedToDeserializeCompactRSRecoverableSignatureInvalidByteCount(
					got: compact.count,
					expected: Self.byteCountRS
				)
			}
			self.compact = compact
			self.recoveryID = recoveryID
		}
	}
}

extension K1.ECDSA.Recoverable.Signature.Compact {
	public static let byteCountRS = 2 * Curve.Field.byteCount
	public static let byteCount = Self.byteCountRS + 1

	/// Takes either `R || S || V` data or `V || R || S` data, as per specification of `format`.
	public init(
		rawRepresentation: some DataProtocol,
		format: SerializationFormat
	) throws {
		guard rawRepresentation.count == Self.byteCount else {
			throw K1.Error.failedToDeserializeCompactRecoverableSignatureInvalidByteCount(got: rawRepresentation.count, expected: Self.byteCount)
		}
		switch format {
		case .vrs:
			try self.init(
				compact: Data(rawRepresentation.suffix(Self.byteCountRS)),
				recoveryID: .init(byte: rawRepresentation.first!) // force unwrap OK since we have checked length above.
			)
		case .rsv:
			try self.init(
				compact: Data(rawRepresentation.prefix(Self.byteCountRS)),
				recoveryID: .init(byte: rawRepresentation.last!) // force unwrap OK since we have checked length above.
			)
		}
	}

	public enum SerializationFormat {
		/// `R || S || V` - the format `libsecp256k1` v0.3.0 uses as internal representation
		/// This is the default value of this library.
		case rsv

		/// We use `R || S || V` as default values since `libsecp256k1` v0.3.0 uses it as its internal representation.
		public static let `default`: Self = .rsv

		/// `V || R || S`.
		case vrs
	}

	private var v: Data {
		recoveryID.vData
	}

	private var rs: Data {
		compact
	}

	func serialize(format: SerializationFormat) -> Data {
		switch format {
		case .rsv:
			return rs + v
		case .vrs:
			return v + rs
		}
	}
}

extension K1.ECDSA.Recoverable.Signature.RecoveryID {
	var vData: Data {
		Data(
			[UInt8(rawValue)]
		)
	}
}

// MARK: Recovery
extension K1.ECDSA.Recoverable.Signature {
	public func recoverPublicKey(
		message: some DataProtocol
	) throws -> K1.ECDSA.Recoverable.PublicKey {
		let wrapped = try FFI.ECDSA.Recovery.recover(wrapped, message: [UInt8](message))
		let impl = K1._PublicKeyImplementation(wrapped: wrapped)
		return K1.ECDSA.Recoverable.PublicKey(
			impl: impl
		)
	}
}

// MARK: Conversion
extension K1.ECDSA.Recoverable.Signature {
	public func nonRecoverable() throws -> K1.ECDSA.NonRecoverable.Signature {
		try K1.ECDSA.NonRecoverable.Signature(
			wrapped: FFI.ECDSA.Recovery.nonRecoverable(self.wrapped)
		)
	}
}

// MARK: Equatable
extension K1.ECDSA.Recoverable.Signature {
	public static func == (lhs: Self, rhs: Self) -> Bool {
		lhs.wrapped.withUnsafeBytes { lhsBytes in
			rhs.wrapped.withUnsafeBytes { rhsBytes in
				safeCompare(lhsBytes, rhsBytes)
			}
		}
	}
}

// MARK: Hashable
extension K1.ECDSA.Recoverable.Signature {
	public func hash(into hasher: inout Hasher) {
		wrapped.withUnsafeBytes {
			hasher.combine(bytes: $0)
		}
	}
}
