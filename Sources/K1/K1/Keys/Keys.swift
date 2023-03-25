// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import Foundation

// MARK: - Schnorr
extension K1.Schnorr {
	// MARK: PrivateKey
	/// private key for schnoriri
	public struct PrivateKey: Sendable, Hashable, K1PrivateKeyProtocol {
		public init() {
			self.init(impl: .init())
		}

		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PrivateKeyImplementation
		internal let impl: Impl
		internal let publicKeyImpl: K1._PublicKeyImplementation

		public typealias PublicKey = K1.Schnorr.PublicKey
		public var publicKey: PublicKey {
			try! .init(rawRepresentation: publicKeyImpl.rawRepresentation)
		}

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
		}
	}

	// MARK: PublicKey
	/// pub key for schnooorrriiii
	public struct PublicKey: Sendable, Hashable, K1PublicKeyProtocol {
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PublicKeyImplementation
		internal let impl: Impl
		internal init(impl: Impl) {
			self.impl = impl
		}
	}
}

// MARK: - KeyAgreement
extension K1.KeyAgreement {
	// MARK: PrivateKey
	/// private key for keyagremt
	public struct PrivateKey: Sendable, Hashable, K1PrivateKeyProtocol {
		public init() {
			self.init(impl: .init())
		}

		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PrivateKeyImplementation
		internal let impl: Impl
		internal let publicKeyImpl: K1._PublicKeyImplementation

		public typealias PublicKey = K1.KeyAgreement.PublicKey
		public var publicKey: PublicKey {
			try! .init(rawRepresentation: publicKeyImpl.rawRepresentation)
		}

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
		}
	}

	// MARK: PublicKey
	/// pub key for ec dh adhd
	public struct PublicKey: Sendable, Hashable, K1PublicKeyProtocol {
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PublicKeyImplementation
		internal let impl: Impl
		internal init(impl: Impl) {
			self.impl = impl
		}
	}
}

// MARK: - ECDSA.NonRecoverable
extension K1.ECDSA.NonRecoverable {
	// MARK: PrivateKey
	/// sign key nonrec
	public struct PrivateKey: Sendable, Hashable, K1PrivateKeyProtocol {
		public init() {
			self.init(impl: .init())
		}

		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PrivateKeyImplementation
		internal let impl: Impl
		internal let publicKeyImpl: K1._PublicKeyImplementation

		public typealias PublicKey = K1.ECDSA.NonRecoverable.PublicKey
		public var publicKey: PublicKey {
			try! .init(rawRepresentation: publicKeyImpl.rawRepresentation)
		}

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
		}
	}

	// MARK: PublicKey
	/// pub key verif key nonrec
	public struct PublicKey: Sendable, Hashable, K1PublicKeyProtocol {
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PublicKeyImplementation
		internal let impl: Impl
		internal init(impl: Impl) {
			self.impl = impl
		}
	}
}

// MARK: - ECDSA.Recoverable
extension K1.ECDSA.Recoverable {
	// MARK: PrivateKey
	/// sign key reccco
	public struct PrivateKey: Sendable, Hashable, K1PrivateKeyProtocol {
		public init() {
			self.init(impl: .init())
		}

		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PrivateKeyImplementation
		internal let impl: Impl
		internal let publicKeyImpl: K1._PublicKeyImplementation

		public typealias PublicKey = K1.ECDSA.Recoverable.PublicKey
		public var publicKey: PublicKey {
			try! .init(rawRepresentation: publicKeyImpl.rawRepresentation)
		}

		init(impl: Impl) {
			self.impl = impl
			self.publicKeyImpl = impl.publicKey
		}
	}

	// MARK: PublicKey
	/// pub key verif key recoo
	public struct PublicKey: Sendable, Hashable, K1PublicKeyProtocol {
		public init(rawRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(rawRepresentation: rawRepresentation))
		}

		public init(compressedRepresentation: some ContiguousBytes) throws {
			try self.init(impl: .init(compressedRepresentation: compressedRepresentation))
		}

		public init(x963Representation: some ContiguousBytes) throws {
			try self.init(impl: .init(x963Representation: x963Representation))
		}

		public init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
			try self.init(impl: .init(derRepresentation: derRepresentation))
		}

		public init(pemRepresentation: String) throws {
			try self.init(impl: .init(pemRepresentation: pemRepresentation))
		}

		public var rawRepresentation: Data {
			impl.rawRepresentation
		}

		public var x963Representation: Data {
			impl.x963Representation
		}

		public var derRepresentation: Data {
			impl.derRepresentation
		}

		public var compressedRepresentation: Data {
			impl.compressedRepresentation
		}

		public var pemRepresentation: String {
			impl.pemRepresentation
		}

		typealias Impl = K1._PublicKeyImplementation
		internal let impl: Impl
		internal init(impl: Impl) {
			self.impl = impl
		}
	}
}

