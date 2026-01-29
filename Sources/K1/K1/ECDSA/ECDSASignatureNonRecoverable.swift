import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// MARK: - K1.ECDSA.Signature
extension K1.ECDSA {
	/// A `secp256k1` elliptic curve digital signature algorithm (ECDSA) signature,
	/// from which users can recover a public key with the message that was signed.
	public struct Signature: Sendable, Hashable, ContiguousBytes {
		typealias Wrapped = FFI.ECDSA.Wrapped
		let wrapped: Wrapped

		init(wrapped: Wrapped) {
			self.wrapped = wrapped
		}
	}
}

// MARK: Inits
extension K1.ECDSA.Signature {
	/// Creates a `secp256k1` ECDSA signature from a Distinguished Encoding Rules (DER) encoded representation.
	/// - Parameter derRepresentation: A DER-encoded representation of the signature.
	public init(derRepresentation: some DataProtocol) throws {
		try self.init(
			wrapped: FFI.ECDSA.from(derRepresentation: [UInt8](derRepresentation))
		)
	}

	/// Creates a `secp256k1` ECDSA signature from the raw representation.
	///
	/// Expects 64 bytes on format: `R || S`, as defined in [rfc4754][rfc]. In
	/// `libsecp256k1` this representation is called "compact".
	///
	/// - Parameter rawRepresentation: A raw representation of the ECDSA signature as a collection of contiguous bytes.
	///
	/// [rfc]: https://tools.ietf.org/html/rfc4754
	public init(rawRepresentation: some DataProtocol) throws {
		try self.init(
			wrapped: FFI.ECDSA.from(compactBytes: [UInt8](rawRepresentation))
		)
	}
}

// MARK: ContiguousBytes
extension K1.ECDSA.Signature {
	public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
		try wrapped.withUnsafeBytes(body)
	}
}

// MARK: Serialize
extension K1.ECDSA.Signature {
	var internalRepresentation: Data {
		Data(wrapped.bytes)
	}

	/// A raw data representation of a `secp256k1` ECDSA non recoverable signature.
	///
	/// Returns 64 bytes on format: `R || S`, as defined in [rfc4754][rfc]. In
	/// `libsecp256k1` this representation is called "compact".
	public var rawRepresentation: Data {
		do {
			return try FFI.ECDSA.compact(wrapped)
		} catch {
			fatalError("Should never fail to convert ECDSA signatures to rawRepresentation.")
		}
	}

	/// A Distinguished Encoding Rules (DER) encoded representation of a
	/// `secp256k1` ECDSA non recoverable signature.
	public var derRepresentation: Data {
		do {
			return try FFI.ECDSA.der(wrapped)
		} catch {
			fatalError("Should never fail to convert ECDSA signatures to DER representation.")
		}
	}
}

extension K1.ECDSA.Signature {
	static let byteCount = FFI.ECDSAWithKeyRecovery.byteCount
}

// MARK: Equatable
extension K1.ECDSA.Signature {
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
extension K1.ECDSA.Signature {
	public func hash(into hasher: inout Hasher) {
		wrapped.withUnsafeBytes {
			hasher.combine(bytes: $0)
		}
	}
}
