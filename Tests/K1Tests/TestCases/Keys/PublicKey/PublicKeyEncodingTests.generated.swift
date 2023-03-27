// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import Foundation
@testable import K1
import XCTest

private extension XCTestCase {
	func doTest<PubKey: _K1PublicKeyProtocol & Equatable, Encoding: Equatable>(
		original makeOriginal: @autoclosure () -> PubKey,
		serialize: KeyPath<PubKey, Encoding>,
		deserialize: (Encoding) throws -> PubKey
	) throws {
		try doTestSerializationRoundtrip(
			original: makeOriginal(),
			serialize: serialize,
			deserialize: deserialize
		)
	}
}

public func doTestSerializationRoundtrip<T, Enc>(
	original makeOriginal: @autoclosure () -> T,
	serialize: KeyPath<T, Enc>,
	deserialize: (Enc) throws -> T
) throws where T: Hashable, Enc: Equatable {
	let count = 100
	var unique = Set<T>()
	for _ in 0 ..< count {
		let original = makeOriginal()
		unique.insert(original)
		let serialized = original[keyPath: serialize]
		let deserialized = try deserialize(serialized)
		XCTAssertEqual(deserialized, original)
		let reserialized = deserialized[keyPath: serialize]
		XCTAssertEqual(reserialized, serialized)
	}
	XCTAssertEqual(unique.count, count)
}

extension K1.Schnorr.PublicKey {
	init() {
		let pubKey = K1.Schnorr.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - SchnorrPublicKeyEncodingDecodingRoundtripTests
final class SchnorrPublicKeyEncodingDecodingRoundtripTests: XCTestCase {
	func test_pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.Schnorr.PrivateKey()
		let publicKey = privateKey.publicKey

		XCTAssertEqual(publicKey.rawRepresentation.hex, Data(publicKey.x963Representation.dropFirst()).hex)
	}

	func testRawRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(rawRepresentation:)
		)
	}

	func testCompressedRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(compressedRepresentation:)
		)
	}

	func testx963Roundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.Schnorr.PublicKey.init(x963Representation:)
		)
	}

	func testDERRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(derRepresentation:)
		)
	}

	func testPEMRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(pemRepresentation:)
		)
	}
}

extension K1.ECDSA.NonRecoverable.PublicKey {
	init() {
		let pubKey = K1.ECDSA.NonRecoverable.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - ECDSANonRecoverablePublicKeyEncodingDecodingRoundtripTests
final class ECDSANonRecoverablePublicKeyEncodingDecodingRoundtripTests: XCTestCase {
	func test_pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.ECDSA.NonRecoverable.PrivateKey()
		let publicKey = privateKey.publicKey

		XCTAssertEqual(publicKey.rawRepresentation.hex, Data(publicKey.x963Representation.dropFirst()).hex)
	}

	func testRawRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.NonRecoverable.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.ECDSA.NonRecoverable.PublicKey.init(rawRepresentation:)
		)
	}

	func testCompressedRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.NonRecoverable.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.ECDSA.NonRecoverable.PublicKey.init(compressedRepresentation:)
		)
	}

	func testx963Roundtrip() throws {
		try doTest(
			original: K1.ECDSA.NonRecoverable.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.ECDSA.NonRecoverable.PublicKey.init(x963Representation:)
		)
	}

	func testDERRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.NonRecoverable.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.ECDSA.NonRecoverable.PublicKey.init(derRepresentation:)
		)
	}

	func testPEMRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.NonRecoverable.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.ECDSA.NonRecoverable.PublicKey.init(pemRepresentation:)
		)
	}
}

extension K1.ECDSA.Recoverable.PublicKey {
	init() {
		let pubKey = K1.ECDSA.Recoverable.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - ECDSARecoverablePublicKeyEncodingDecodingRoundtripTests
final class ECDSARecoverablePublicKeyEncodingDecodingRoundtripTests: XCTestCase {
	func test_pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.ECDSA.Recoverable.PrivateKey()
		let publicKey = privateKey.publicKey

		XCTAssertEqual(publicKey.rawRepresentation.hex, Data(publicKey.x963Representation.dropFirst()).hex)
	}

	func testRawRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.Recoverable.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.ECDSA.Recoverable.PublicKey.init(rawRepresentation:)
		)
	}

	func testCompressedRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.Recoverable.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.ECDSA.Recoverable.PublicKey.init(compressedRepresentation:)
		)
	}

	func testx963Roundtrip() throws {
		try doTest(
			original: K1.ECDSA.Recoverable.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.ECDSA.Recoverable.PublicKey.init(x963Representation:)
		)
	}

	func testDERRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.Recoverable.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.ECDSA.Recoverable.PublicKey.init(derRepresentation:)
		)
	}

	func testPEMRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.Recoverable.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.ECDSA.Recoverable.PublicKey.init(pemRepresentation:)
		)
	}
}

extension K1.KeyAgreement.PublicKey {
	init() {
		let pubKey = K1.KeyAgreement.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - KeyAgreementPublicKeyEncodingDecodingRoundtripTests
final class KeyAgreementPublicKeyEncodingDecodingRoundtripTests: XCTestCase {
	func test_pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.KeyAgreement.PrivateKey()
		let publicKey = privateKey.publicKey

		XCTAssertEqual(publicKey.rawRepresentation.hex, Data(publicKey.x963Representation.dropFirst()).hex)
	}

	func testRawRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(rawRepresentation:)
		)
	}

	func testCompressedRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(compressedRepresentation:)
		)
	}

	func testx963Roundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.KeyAgreement.PublicKey.init(x963Representation:)
		)
	}

	func testDERRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(derRepresentation:)
		)
	}

	func testPEMRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(pemRepresentation:)
		)
	}
}
