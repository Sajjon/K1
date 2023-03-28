import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// MARK: - K1.ECDSAWithKeyRecovery
extension K1 {
	/// A mechanism used to create or verify a cryptographic signature using the `secp256k1` elliptic curve digital signature algorithm (ECDSA), signatures that do offers recovery of the public key.
	public enum ECDSAWithKeyRecovery {
		// Just a namespace
	}
}

// MARK: - K1.ECDSAWithKeyRecovery.Signature
extension K1.ECDSAWithKeyRecovery {
	/// A `secp256k1` elliptic curve digital signature algorithm (ECDSA) signature,
	/// from which users **cannot** recover the public key, not without the `RecoveryID`.
	public struct Signature: Sendable, Hashable, ContiguousBytes {
		typealias Wrapped = FFI.ECDSAWithKeyRecovery.Wrapped
		internal let wrapped: Wrapped

		internal init(wrapped: Wrapped) {
			self.wrapped = wrapped
		}
	}
}

// MARK: Init
extension K1.ECDSAWithKeyRecovery.Signature {
	/// Compact aka `IEEE P1363` aka `R||S`.
	public init(compact: Compact) throws {
		try self.init(
			wrapped: FFI.ECDSAWithKeyRecovery.deserialize(
				compact: [UInt8](compact.compact),
				recoveryID: compact.recoveryID.recid
			)
		)
	}

	/// Compact aka `IEEE P1363` aka `R||S`.
	public init(compact: Data, recoveryID: RecoveryID) throws {
		try self.init(compact: .init(compact: compact, recoveryID: recoveryID))
	}

	init(
		internalRepresentation: some DataProtocol
	) throws {
		try self.init(
			wrapped: FFI.ECDSAWithKeyRecovery.deserialize(rawRepresentation: internalRepresentation)
		)
	}
}

// MARK: ContiguousBytes
extension K1.ECDSAWithKeyRecovery.Signature {
	public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try wrapped.withUnsafeBytes(body)
	}
}

// MARK: Serialize
extension K1.ECDSAWithKeyRecovery.Signature {
	internal var internalRepresentation: Data {
		Data(wrapped.bytes)
	}

	/// Compact aka `IEEE P1363` aka `R||S` with `RecoveryID`
	public func compact() throws -> Compact {
		let (rs, recid) = try FFI.ECDSAWithKeyRecovery.serializeCompact(
			wrapped
		)
		return try .init(
			compact: Data(rs),
			recoveryID: .init(recid: recid)
		)
	}

	/// A tuple of `R||S` and `recoveryID` from a recoverable ECDSA signature.
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
				throw K1.Error.incorrectKeySize
			}
			self.compact = compact
			self.recoveryID = recoveryID
		}
	}
}

extension K1.ECDSAWithKeyRecovery.Signature.Compact {
	public static let byteCountRS = 2 * Curve.Field.byteCount
	public static let byteCount = Self.byteCountRS + 1

	/// Takes either `R || S || V` data or `V || R || S` data, as per specification of `format`.
	public init(
		rawRepresentation: some DataProtocol,
		format: SerializationFormat
	) throws {
		guard rawRepresentation.count == Self.byteCount else {
			throw K1.Error.incorrectKeySize
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

extension K1.ECDSAWithKeyRecovery.Signature.RecoveryID {
	var vData: Data {
		Data(
			[UInt8(rawValue)]
		)
	}
}

// MARK: Recovery
extension K1.ECDSAWithKeyRecovery.Signature {
	/// Recovers a public key from a `secp256k1` this ECDSA signature and the message signed.
	///
	/// - Parameters:
	///   - message: The message that was signed to produce this ECDSA signature.
	/// - Returns: The public key which corresponds to the private key which used to produce this
	/// signature by signing the `message`.
	public func recoverPublicKey(
		message: some DataProtocol
	) throws -> K1.ECDSAWithKeyRecovery.PublicKey {
		let wrapped = try FFI.ECDSAWithKeyRecovery.recover(wrapped, message: [UInt8](message))
		let impl = K1._PublicKeyImplementation(wrapped: wrapped)
		return K1.ECDSAWithKeyRecovery.PublicKey(
			impl: impl
		)
	}
}

// MARK: Conversion
extension K1.ECDSAWithKeyRecovery.Signature {
	/// Converts this recoverable ECDSA signature to a non-recoverable version.
	public func nonRecoverable() throws -> K1.ECDSA.Signature {
		try K1.ECDSA.Signature(
			wrapped: FFI.ECDSAWithKeyRecovery.nonRecoverable(self.wrapped)
		)
	}
}

// MARK: Equatable
extension K1.ECDSAWithKeyRecovery.Signature {
	/// Compares two ECDSA signatures.
	public static func == (lhs: Self, rhs: Self) -> Bool {
		lhs.wrapped.withUnsafeBytes { lhsBytes in
			rhs.wrapped.withUnsafeBytes { rhsBytes in
				safeCompare(lhsBytes, rhsBytes)
			}
		}
	}
}

// MARK: Hashable
extension K1.ECDSAWithKeyRecovery.Signature {
	public func hash(into hasher: inout Hasher) {
		wrapped.withUnsafeBytes {
			hasher.combine(bytes: $0)
		}
	}
}
