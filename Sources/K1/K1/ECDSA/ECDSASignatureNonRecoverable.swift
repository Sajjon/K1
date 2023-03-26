import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// MARK: - K1.ECDSA.NonRecoverable
extension K1.ECDSA {
	/// A mechanism used to create or verify a cryptographic signature using the `secp256k1` elliptic curve digital signature algorithm (ECDSA), signatures that do not offer recovery of the public key.
	public enum NonRecoverable {
		// Just a namespace
	}
}

// MARK: - K1.ECDSA.NonRecoverable.Signature
extension K1.ECDSA.NonRecoverable {
	/// A `secp256k1` elliptic curve digital signature algorithm (ECDSA) signature,
	/// from which users can recover a public key with the message that was signed.
	public struct Signature: Sendable, Hashable, ContiguousBytes {
		typealias Wrapped = FFI.ECDSA.NonRecoverable.Wrapped
		internal let wrapped: Wrapped

		init(wrapped: Wrapped) {
			self.wrapped = wrapped
		}
	}
}

// MARK: Inits
extension K1.ECDSA.NonRecoverable.Signature {
	public init(compactRepresentation: some DataProtocol) throws {
		try self.init(
			wrapped: FFI.ECDSA.NonRecoverable.from(compactBytes: [UInt8](compactRepresentation))
		)
	}

	public init(derRepresentation: some DataProtocol) throws {
		try self.init(
			wrapped: FFI.ECDSA.NonRecoverable.from(derRepresentation: [UInt8](derRepresentation))
		)
	}
}

// MARK: ContiguousBytes
extension K1.ECDSA.NonRecoverable.Signature {
	public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try wrapped.withUnsafeBytes(body)
	}
}

// MARK: Serialize
extension K1.ECDSA.NonRecoverable.Signature {
	internal var rawRepresentation: Data {
		Data(wrapped.bytes)
	}

	public func compactRepresentation() throws -> Data {
		try FFI.ECDSA.NonRecoverable.compact(wrapped)
	}

	public func derRepresentation() throws -> Data {
		try FFI.ECDSA.NonRecoverable.der(wrapped)
	}
}

// MARK: Recover
extension K1.ECDSA.NonRecoverable.Signature {
	public func recoverPublicKey(
		recoveryID: K1.ECDSA.Recoverable.Signature.RecoveryID,
		message: some DataProtocol
	) throws -> K1.ECDSA.NonRecoverable.PublicKey {
		let wrapped = try FFI.ECDSA.NonRecoverable.recoverPublicKey(
			self.wrapped,
			recoveryID: recoveryID.recid,
			message: [UInt8](message)
		)
		let impl = K1._PublicKeyImplementation(wrapped: wrapped)
		return K1.ECDSA.NonRecoverable.PublicKey(impl: impl)
	}
}

extension K1.ECDSA.NonRecoverable.Signature {
	internal static let byteCount = FFI.ECDSA.Recoverable.byteCount
}

// MARK: Equatable
extension K1.ECDSA.NonRecoverable.Signature {
	public static func == (lhs: Self, rhs: Self) -> Bool {
		lhs.wrapped.withUnsafeBytes { lhsBytes in
			rhs.wrapped.withUnsafeBytes { rhsBytes in
				safeCompare(lhsBytes, rhsBytes)
			}
		}
	}
}

// MARK: Hashable
extension K1.ECDSA.NonRecoverable.Signature {
	public func hash(into hasher: inout Hasher) {
		wrapped.withUnsafeBytes {
			hasher.combine(bytes: $0)
		}
	}
}
