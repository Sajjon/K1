// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import Foundation

// swiftlint:disable all

extension K1.KeyAgreement {
	// MARK: KeyAgreement + PrivateKey
	/// A `secp256k1` private key used for key agreement.
	public struct PrivateKey: Sendable, Hashable {
		typealias Impl = K1._PrivateKeyImplementation
		public typealias PublicKey = K1.KeyAgreement.PublicKey

		let impl: Impl
		let publicKeyImpl: K1._PublicKeyImplementation

		/// The corresponding public key.
		public let publicKey: PublicKey

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
			do {
				self.publicKey = try PublicKey(rawRepresentation: impl.publicKey.rawRepresentation)
			} catch {
				fatalError("Should never fail to instantiate a PublicKey from a PrivateKey, error: \(error)")
			}
		}

		/// Creates a random `secp256k1` private key for key agreement.
		public init() {
			self.init(impl: .init())
		}

		/// Creates a `secp256k1` private key for key agreement from a data representation of the key.
		///
		/// Expects 32 bytes representation of a UInt256 scalar.
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` private key for key agreement from a Distinguished Encoding Rules (DER) encoded representation of the key.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` private key for key agreement from a Privacy-Enhanced Mail (PEM) representation of the key.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` private key for key agreement from an ANSI x9.63 representation of the key.
		///
		/// Expects 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// A representation of the private key as a collection of bytes.
		///
		/// Returns 32 bytes representation of a UInt256 scalar.
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the private key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the private key.
		///
		/// Returns a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the private key.
		///
		/// Returns 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		public var x963Representation: Data {
			impl.x963Representation
		}
	}

	// MARK: KeyAgreement + PublicKey
	/// A `secp256k1` public key used for key agreement.
	public struct PublicKey: Sendable, Hashable {
		typealias Impl = K1._PublicKeyImplementation
		let impl: Impl
		init(impl: Impl) {
			self.impl = impl
		}

		/// Creates a `secp256k1` public key for key agreement from a collection of bytes.
		///
		///	Expects 64 bytes on format `X || Y`, i.e. X- and Y-coordinates, as two
		///	32 byte sequences (UInt256 integers).
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` public key for key agreement from a Distinguished Encoding Rules (DER) encoded representation.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` public key for key agreement from a Privacy-Enhanced Mail (PEM) representation.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PUBLIC KEY-----
		///		MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEmDCEiyeJE4a9RUb7eDDriO1TXxZaIHT
		///		7rrSHzfdh4xcmgwamt52c3qIEb1qf5KHyXjuOWqonBHkcinSzLVS8A==
		///	 	-----END PUBLIC KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` public key for key agreement from an ANSI x9.63 representation.
		///
		/// Expects 65 bytes on format `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// Creates a `secp256k1` public key for key agreement from a compressed representation of the key.
		///
		/// Expects 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		/// - Parameter compressedRepresentation: A compressed representation of the key as a collection of contiguous bytes.
		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		/// A full representation of the public key.
		///
		/// Returns 64 bytes on format: `X || Y`
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the public key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the public key.
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the public key.
		///
		/// Returns 65 bytes on format: `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		public var x963Representation: Data {
			impl.x963Representation
		}

		/// A compressed representation of the public key.
		///
		/// Returns 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		// MARK: Group Operations

		/// Adds two public keys (points) on the secp256k1 curve
		public static func + (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl + rhs.impl)
		}

		/// Subtracts two public keys (points) on the secp256k1 curve
		public static func - (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl - rhs.impl)
		}

		/// Negates a public key (point) on the secp256k1 curve
		public func negate() throws -> Self {
			try Self(impl: impl.negate())
		}

		/// Combines multiple public keys (points) on the secp256k1 curve
		public static func sum(keys: [Self]) throws -> Self {
			let impls = keys.map(\.impl)
			return try Self(impl: K1._PublicKeyImplementation.sum(keys: impls))
		}
	}
}

extension K1.Schnorr {
	// MARK: Schnorr + PrivateKey
	/// A `secp256k1` private key used to create cryptographic signatures,
	/// more specifically Schnorr signatures.
	public struct PrivateKey: Sendable, Hashable {
		typealias Impl = K1._PrivateKeyImplementation
		public typealias PublicKey = K1.Schnorr.PublicKey

		let impl: Impl
		let publicKeyImpl: K1._PublicKeyImplementation

		/// The corresponding public key.
		public let publicKey: PublicKey

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
			do {
				self.publicKey = try PublicKey(rawRepresentation: impl.publicKey.rawRepresentation)
			} catch {
				fatalError("Should never fail to instantiate a PublicKey from a PrivateKey, error: \(error)")
			}
		}

		/// Creates a random `secp256k1` private key for signing.
		public init() {
			self.init(impl: .init())
		}

		/// Creates a `secp256k1` private key for signing from a data representation of the key.
		///
		/// Expects 32 bytes representation of a UInt256 scalar.
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from a Distinguished Encoding Rules (DER) encoded representation of the key.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from a Privacy-Enhanced Mail (PEM) representation of the key.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from an ANSI x9.63 representation of the key.
		///
		/// Expects 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// A representation of the private key as a collection of bytes.
		///
		/// Returns 32 bytes representation of a UInt256 scalar.
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the private key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the private key.
		///
		/// Returns a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the private key.
		///
		/// Returns 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		public var x963Representation: Data {
			impl.x963Representation
		}
	}

	// MARK: Schnorr + PublicKey
	/// A `secp256k1` public key used to verify cryptographic signatures,
	/// more specifically Schnorr signatures
	public struct PublicKey: Sendable, Hashable {
		typealias Impl = K1._PublicKeyImplementation
		let impl: Impl
		init(impl: Impl) {
			self.impl = impl
		}

		/// Creates a `secp256k1` public key for verifying signatures from a collection of bytes.
		///
		///	Expects 64 bytes on format `X || Y`, i.e. X- and Y-coordinates, as two
		///	32 byte sequences (UInt256 integers).
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a Distinguished Encoding Rules (DER) encoded representation.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a Privacy-Enhanced Mail (PEM) representation.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PUBLIC KEY-----
		///		MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEmDCEiyeJE4a9RUb7eDDriO1TXxZaIHT
		///		7rrSHzfdh4xcmgwamt52c3qIEb1qf5KHyXjuOWqonBHkcinSzLVS8A==
		///	 	-----END PUBLIC KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from an ANSI x9.63 representation.
		///
		/// Expects 65 bytes on format `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a compressed representation of the key.
		///
		/// Expects 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		/// - Parameter compressedRepresentation: A compressed representation of the key as a collection of contiguous bytes.
		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		/// A full representation of the public key.
		///
		/// Returns 64 bytes on format: `X || Y`
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the public key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the public key.
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the public key.
		///
		/// Returns 65 bytes on format: `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		public var x963Representation: Data {
			impl.x963Representation
		}

		/// A compressed representation of the public key.
		///
		/// Returns 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		// MARK: Group Operations

		/// Adds two public keys (points) on the secp256k1 curve
		public static func + (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl + rhs.impl)
		}

		/// Subtracts two public keys (points) on the secp256k1 curve
		public static func - (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl - rhs.impl)
		}

		/// Negates a public key (point) on the secp256k1 curve
		public func negate() throws -> Self {
			try Self(impl: impl.negate())
		}

		/// Combines multiple public keys (points) on the secp256k1 curve
		public static func sum(keys: [Self]) throws -> Self {
			let impls = keys.map(\.impl)
			return try Self(impl: K1._PublicKeyImplementation.sum(keys: impls))
		}
	}
}

extension K1.ECDSA {
	// MARK: ECDSA + PrivateKey
	/// A `secp256k1` private key used to create cryptographic signatures,
	/// more specifically ECDSA signatures, that do not offer recovery of the public key.
	public struct PrivateKey: Sendable, Hashable {
		typealias Impl = K1._PrivateKeyImplementation
		public typealias PublicKey = K1.ECDSA.PublicKey

		let impl: Impl
		let publicKeyImpl: K1._PublicKeyImplementation

		/// The corresponding public key.
		public let publicKey: PublicKey

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
			do {
				self.publicKey = try PublicKey(rawRepresentation: impl.publicKey.rawRepresentation)
			} catch {
				fatalError("Should never fail to instantiate a PublicKey from a PrivateKey, error: \(error)")
			}
		}

		/// Creates a random `secp256k1` private key for signing.
		public init() {
			self.init(impl: .init())
		}

		/// Creates a `secp256k1` private key for signing from a data representation of the key.
		///
		/// Expects 32 bytes representation of a UInt256 scalar.
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from a Distinguished Encoding Rules (DER) encoded representation of the key.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from a Privacy-Enhanced Mail (PEM) representation of the key.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from an ANSI x9.63 representation of the key.
		///
		/// Expects 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// A representation of the private key as a collection of bytes.
		///
		/// Returns 32 bytes representation of a UInt256 scalar.
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the private key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the private key.
		///
		/// Returns a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the private key.
		///
		/// Returns 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		public var x963Representation: Data {
			impl.x963Representation
		}
	}

	// MARK: ECDSA + PublicKey
	/// A `secp256k1` public key used to verify cryptographic signatures,
	/// more specifically ECDSA signatures, that do not offer recovery of the public key.
	public struct PublicKey: Sendable, Hashable {
		typealias Impl = K1._PublicKeyImplementation
		let impl: Impl
		init(impl: Impl) {
			self.impl = impl
		}

		/// Creates a `secp256k1` public key for verifying signatures from a collection of bytes.
		///
		///	Expects 64 bytes on format `X || Y`, i.e. X- and Y-coordinates, as two
		///	32 byte sequences (UInt256 integers).
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a Distinguished Encoding Rules (DER) encoded representation.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a Privacy-Enhanced Mail (PEM) representation.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PUBLIC KEY-----
		///		MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEmDCEiyeJE4a9RUb7eDDriO1TXxZaIHT
		///		7rrSHzfdh4xcmgwamt52c3qIEb1qf5KHyXjuOWqonBHkcinSzLVS8A==
		///	 	-----END PUBLIC KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from an ANSI x9.63 representation.
		///
		/// Expects 65 bytes on format `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a compressed representation of the key.
		///
		/// Expects 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		/// - Parameter compressedRepresentation: A compressed representation of the key as a collection of contiguous bytes.
		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		/// A full representation of the public key.
		///
		/// Returns 64 bytes on format: `X || Y`
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the public key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the public key.
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the public key.
		///
		/// Returns 65 bytes on format: `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		public var x963Representation: Data {
			impl.x963Representation
		}

		/// A compressed representation of the public key.
		///
		/// Returns 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		// MARK: Group Operations

		/// Adds two public keys (points) on the secp256k1 curve
		public static func + (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl + rhs.impl)
		}

		/// Subtracts two public keys (points) on the secp256k1 curve
		public static func - (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl - rhs.impl)
		}

		/// Negates a public key (point) on the secp256k1 curve
		public func negate() throws -> Self {
			try Self(impl: impl.negate())
		}

		/// Combines multiple public keys (points) on the secp256k1 curve
		public static func sum(keys: [Self]) throws -> Self {
			let impls = keys.map(\.impl)
			return try Self(impl: K1._PublicKeyImplementation.sum(keys: impls))
		}
	}
}

extension K1.ECDSAWithKeyRecovery {
	// MARK: ECDSAWithKeyRecovery + PrivateKey
	/// A `secp256k1` private key used to create cryptographic signatures,
	/// more specifically ECDSA signatures that offers recovery of the public key.
	public struct PrivateKey: Sendable, Hashable {
		typealias Impl = K1._PrivateKeyImplementation
		public typealias PublicKey = K1.ECDSAWithKeyRecovery.PublicKey

		let impl: Impl
		let publicKeyImpl: K1._PublicKeyImplementation

		/// The corresponding public key.
		public let publicKey: PublicKey

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
			do {
				self.publicKey = try PublicKey(rawRepresentation: impl.publicKey.rawRepresentation)
			} catch {
				fatalError("Should never fail to instantiate a PublicKey from a PrivateKey, error: \(error)")
			}
		}

		/// Creates a random `secp256k1` private key for signing.
		public init() {
			self.init(impl: .init())
		}

		/// Creates a `secp256k1` private key for signing from a data representation of the key.
		///
		/// Expects 32 bytes representation of a UInt256 scalar.
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from a Distinguished Encoding Rules (DER) encoded representation of the key.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from a Privacy-Enhanced Mail (PEM) representation of the key.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` private key for signing from an ANSI x9.63 representation of the key.
		///
		/// Expects 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// A representation of the private key as a collection of bytes.
		///
		/// Returns 32 bytes representation of a UInt256 scalar.
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the private key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the private key.
		///
		/// Returns a string on format:
		///
		/// 	-----BEGIN PRIVATE KEY-----
		///		MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgvddDDSbMRcLWZETSUOyD
		///		NIr6bL2F1/hw/rkkjELYhVihRANCAAQGOLtZWXDFwKhJhA6mEoorRokGwohvxe1D
		///		MXhk8/iiD9ZtUygoHEl7AT88R8IYcrqp403A1b+w4LvM0Ih64rQc
		///		-----END PRIVATE KEY-----
		///
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the private key.
		///
		/// Returns 97 bytes on format `04 || X || Y || D`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates of its public key and then the private
		/// key itself (UInt256 integers).
		///
		public var x963Representation: Data {
			impl.x963Representation
		}
	}

	// MARK: ECDSAWithKeyRecovery + PublicKey
	/// A `secp256k1` public key used to verify cryptographic signatures.
	/// more specifically ECDSA signatures that offers recovery of the public key.
	public struct PublicKey: Sendable, Hashable {
		typealias Impl = K1._PublicKeyImplementation
		let impl: Impl
		init(impl: Impl) {
			self.impl = impl
		}

		/// Creates a `secp256k1` public key for verifying signatures from a collection of bytes.
		///
		///	Expects 64 bytes on format `X || Y`, i.e. X- and Y-coordinates, as two
		///	32 byte sequences (UInt256 integers).
		///
		/// - Parameter rawRepresentation: A raw representation of the key as a collection of contiguous bytes.
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a Distinguished Encoding Rules (DER) encoded representation.
		/// - Parameter derRepresentation: A DER-encoded representation of the key.
		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a Privacy-Enhanced Mail (PEM) representation.
		///
		/// Expects a string on format:
		///
		/// 	-----BEGIN PUBLIC KEY-----
		///		MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEEmDCEiyeJE4a9RUb7eDDriO1TXxZaIHT
		///		7rrSHzfdh4xcmgwamt52c3qIEb1qf5KHyXjuOWqonBHkcinSzLVS8A==
		///	 	-----END PUBLIC KEY-----
		///
		/// - Parameter pemRepresentation: A PEM representation of the key.
		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from an ANSI x9.63 representation.
		///
		/// Expects 65 bytes on format `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		///
		/// - Parameter x963Representation: An ANSI x9.63 representation of the key.
		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		/// Creates a `secp256k1` public key for verifying signatures from a compressed representation of the key.
		///
		/// Expects 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		/// - Parameter compressedRepresentation: A compressed representation of the key as a collection of contiguous bytes.
		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		/// A full representation of the public key.
		///
		/// Returns 64 bytes on format: `X || Y`
		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		/// A Distinguished Encoding Rules (DER) encoded representation of the public key.
		public var derRepresentation: Data {
			impl.derRepresentation
		}

		/// A Privacy-Enhanced Mail (PEM) representation of the public key.
		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		/// An ANSI x9.63 representation of the public key.
		///
		/// Returns 65 bytes on format: `04 || X || Y`, i.e. the byte prefix `04`,
		/// followed by 32 bytes X- and Y-coordinates (UInt256 integers).
		public var x963Representation: Data {
			impl.x963Representation
		}

		/// A compressed representation of the public key.
		///
		/// Returns 33 bytes on format: `02|03 || X`, i.e. either `02` or `03,
		/// followed by 32 bytes X-coordinate (UInt256 integer).
		///
		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		// MARK: Group Operations

		/// Adds two public keys (points) on the secp256k1 curve
		public static func + (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl + rhs.impl)
		}

		/// Subtracts two public keys (points) on the secp256k1 curve
		public static func - (lhs: Self, rhs: Self) throws -> Self {
			try Self(impl: lhs.impl - rhs.impl)
		}

		/// Negates a public key (point) on the secp256k1 curve
		public func negate() throws -> Self {
			try Self(impl: impl.negate())
		}

		/// Combines multiple public keys (points) on the secp256k1 curve
		public static func sum(keys: [Self]) throws -> Self {
			let impls = keys.map(\.impl)
			return try Self(impl: K1._PublicKeyImplementation.sum(keys: impls))
		}
	}
}

extension K1.KeyAgreement.PrivateKey: _K1PrivateKeyProtocol {}
extension K1.KeyAgreement.PublicKey: _K1PublicKeyProtocol {}
extension K1.Schnorr.PrivateKey: _K1PrivateKeyProtocol {}
extension K1.Schnorr.PublicKey: _K1PublicKeyProtocol {}
extension K1.ECDSA.PrivateKey: _K1PrivateKeyProtocol {}
extension K1.ECDSA.PublicKey: _K1PublicKeyProtocol {}
extension K1.ECDSAWithKeyRecovery.PrivateKey: _K1PrivateKeyProtocol {}
extension K1.ECDSAWithKeyRecovery.PublicKey: _K1PublicKeyProtocol {}

// swiftlint:enable all
