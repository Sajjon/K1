import CryptoKit
import Foundation

// MARK: - K1KeyExportable
public protocol K1KeyExportable {
	var rawRepresentation: Data { get }
	var x963Representation: Data { get }
	var derRepresentation: Data { get }
	var pemRepresentation: String { get }
}

// MARK: - K1KeyImportable
public protocol K1KeyImportable {
	init(rawRepresentation: some ContiguousBytes) throws
	init(x963Representation: some ContiguousBytes) throws
	init(derRepresentation: some RandomAccessCollection<UInt8>) throws
	init(pemRepresentation: String) throws
}

public typealias K1KeyPortable = K1KeyImportable & K1KeyExportable

// MARK: - K1PrivateKeyProtocol
public protocol K1PrivateKeyProtocol: K1KeyPortable {
	associatedtype PublicKey: K1PublicKeyProtocol
	var publicKey: PublicKey { get }
	init()
}

// MARK: - PrivateKey
extension K1 {
	struct _PrivateKeyImplementation: Sendable, Hashable, K1PrivateKeyProtocol {
		typealias Wrapped = FFI.PrivateKey.Wrapped
		internal let wrapped: Wrapped

		let publicKey: _PublicKeyImplementation

		internal init(wrapped: Wrapped) {
			self.wrapped = wrapped
			self.publicKey = PublicKey(wrapped: wrapped.publicKey)
		}
	}
}

// MARK: Inits
extension K1._PrivateKeyImplementation {
	/// Creates a `secp256k1` private key from a Privacy-Enhanced Mail (PEM) representation.
	init(
		pemRepresentation: String
	) throws {
		let pem = try ASN1.PEMDocument(pemString: pemRepresentation)

		switch pem.type {
		case "EC \(Self.pemType)":
			let parsed = try ASN1.SEC1PrivateKey(asn1Encoded: Array(pem.derBytes))
			self = try .init(rawRepresentation: parsed.privateKey)
		case Self.pemType:
			let parsed = try ASN1.PKCS8PrivateKey(asn1Encoded: Array(pem.derBytes))
			self = try .init(rawRepresentation: parsed.privateKey.privateKey)
		default:
			throw K1.Error.invalidPEMDocument
		}
	}

	init(
		rawRepresentation: some ContiguousBytes
	) throws {
		try self.init(
			wrapped: FFI.PrivateKey.deserialize(rawRepresentation: rawRepresentation)
		)
	}

	init(
		x963Representation: some ContiguousBytes
	) throws {
		let length = x963Representation.withUnsafeBytes { $0.count }
		guard length == Self.x963ByteCount else {
			throw K1.Error.incorrectByteCountOfX963PrivateKey(got: length, expected: Self.x963ByteCount)
		}

		let publicKeyX963 = x963Representation.bytes.prefix(K1._PublicKeyImplementation.x963ByteCount)
		let publicKeyFromX963 = try K1._PublicKeyImplementation(x963Representation: publicKeyX963)
		let privateKeyRaw = x963Representation.bytes.suffix(Self.rawByteCount)
		try self.init(rawRepresentation: privateKeyRaw)
		guard self.publicKey == publicKeyFromX963 else {
			throw K1.Error.invalidPrivateX963RepresentationPublicKeyDiscrepancy
		}
		// All good
	}

	/// `DER`
	init(derRepresentation: some RandomAccessCollection<UInt8>) throws {
		let bytes = Array(derRepresentation)

		// We have to try to parse this twice because we have no informaton about what kind of key this is.
		// We try with PKCS#8 first, and then fall back to SEC.1.
		do {
			let key = try ASN1.PKCS8PrivateKey(asn1Encoded: bytes)
			self = try .init(rawRepresentation: key.privateKey.privateKey)
		} catch {
			let key = try ASN1.SEC1PrivateKey(asn1Encoded: bytes)
			self = try .init(rawRepresentation: key.privateKey)
		}
	}

	init() {
		self.init(wrapped: .init())
	}
}

// MARK: Serialize
extension K1._PrivateKeyImplementation {
	/// A raw representation of the private key.
	var rawRepresentation: Data {
		Data(wrapped.secureBytes.bytes)
	}

	/// A Distinguished Encoding Rules (DER) encoded representation of the private key.
	var derRepresentation: Data {
		let pkey = ASN1.PKCS8PrivateKey(
			algorithm: .secp256k1,
			privateKey: Array(self.rawRepresentation),
			publicKey: Array(self.publicKey.x963Representation)
		)
		var serializer = ASN1.Serializer()

		// Serializing these keys can't throw
		try! serializer.serialize(pkey)
		return Data(serializer.serializedBytes)
	}

	/// A Privacy-Enhanced Mail (PEM) representation of the private key.
	var pemRepresentation: String {
		let pemDocument = ASN1.PEMDocument(type: Self.pemType, derBytes: self.derRepresentation)
		return pemDocument.pemString
	}

	/// An ANSI x9.63 representation of the private key.
	var x963Representation: Data {
		// The x9.63 private key format is a discriminator byte (0x4) concatenated with the X and Y points
		// of the key, and the K value of the secret scalar. Let's load that in.
		var bytes = Data()
		bytes.reserveCapacity(Self.x963ByteCount)
		bytes.append(contentsOf: publicKey.x963Representation)
		bytes.append(self.rawRepresentation)
		return bytes
	}

	static let rawByteCount = Curve.Field.byteCount
	static let x963ByteCount = K1._PublicKeyImplementation.x963ByteCount + K1._PrivateKeyImplementation.rawByteCount
}

extension K1._PrivateKeyImplementation {
	static let pemType = "PRIVATE KEY"
}

// MARK: - Equatable
extension K1._PrivateKeyImplementation {
	/// Constant-time comparision.
	static func == (lhs: Self, rhs: Self) -> Bool {
		lhs.wrapped.secureBytes == rhs.wrapped.secureBytes
	}
}

// MARK: - Hashable
extension K1._PrivateKeyImplementation {
	/// We use the key of the private key as input to hash
	func hash(into hasher: inout Hasher) {
		hasher.combine(self.publicKey)
	}
}
