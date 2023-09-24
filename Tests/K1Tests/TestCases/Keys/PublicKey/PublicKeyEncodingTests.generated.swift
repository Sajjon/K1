// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

import Foundation
@testable import K1
import Testing

private func doTest<PubKey: _K1PublicKeyProtocol & Equatable, Encoding: Equatable>(
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
		#expect(deserialized == original)
		let reserialized = deserialized[keyPath: serialize]
		#expect(reserialized == serialized)
	}
	#expect(unique.count == count)
}

extension K1.Schnorr.PublicKey {
	init() {
		let pubKey = K1.Schnorr.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - SchnorrPublicKeyEncodingDecodingRoundtripTests
@Suite("K1.Schnorr.PublicKey")
struct SchnorrPublicKeyEncodingDecodingRoundtripTests {
	@Test
	func pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.Schnorr.PrivateKey()
		let publicKey = privateKey.publicKey
		#expect(publicKey.rawRepresentation.hex == Data(publicKey.x963Representation.dropFirst()).hex)
	}

	@Test
	func rawRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(rawRepresentation:)
		)
	}

	@Test
	func compressedRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(compressedRepresentation:)
		)
	}

	@Test
	func x963Roundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.Schnorr.PublicKey.init(x963Representation:)
		)
	}

	@Test
	func derRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(derRepresentation:)
		)
	}

	@Test
	func pemRoundtrip() throws {
		try doTest(
			original: K1.Schnorr.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.Schnorr.PublicKey.init(pemRepresentation:)
		)
	}
}

extension K1.ECDSA.PublicKey {
	init() {
		let pubKey = K1.ECDSA.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - ECDSAPublicKeyEncodingDecodingRoundtripTests
@Suite("K1.ECDSA.PublicKey")
struct ECDSAPublicKeyEncodingDecodingRoundtripTests {
	@Test
	func pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.ECDSA.PrivateKey()
		let publicKey = privateKey.publicKey
		#expect(publicKey.rawRepresentation.hex == Data(publicKey.x963Representation.dropFirst()).hex)
	}

	@Test
	func rawRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.ECDSA.PublicKey.init(rawRepresentation:)
		)
	}

	@Test
	func compressedRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.ECDSA.PublicKey.init(compressedRepresentation:)
		)
	}

	@Test
	func x963Roundtrip() throws {
		try doTest(
			original: K1.ECDSA.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.ECDSA.PublicKey.init(x963Representation:)
		)
	}

	@Test
	func derRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.ECDSA.PublicKey.init(derRepresentation:)
		)
	}

	@Test
	func pemRoundtrip() throws {
		try doTest(
			original: K1.ECDSA.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.ECDSA.PublicKey.init(pemRepresentation:)
		)
	}
}

extension K1.ECDSAWithKeyRecovery.PublicKey {
	init() {
		let pubKey = K1.ECDSAWithKeyRecovery.PrivateKey().publicKey
		try! self.init(compressedRepresentation: pubKey.compressedRepresentation)
	}
}

// MARK: - ECDSAWithKeyRecoveryPublicKeyEncodingDecodingRoundtripTests
@Suite("K1.ECDSAWithKeyRecovery.PublicKey")
struct ECDSAWithKeyRecoveryPublicKeyEncodingDecodingRoundtripTests {
	@Test
	func pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.ECDSAWithKeyRecovery.PrivateKey()
		let publicKey = privateKey.publicKey
		#expect(publicKey.rawRepresentation.hex == Data(publicKey.x963Representation.dropFirst()).hex)
	}

	@Test
	func rawRoundtrip() throws {
		try doTest(
			original: K1.ECDSAWithKeyRecovery.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.ECDSAWithKeyRecovery.PublicKey.init(rawRepresentation:)
		)
	}

	@Test
	func compressedRoundtrip() throws {
		try doTest(
			original: K1.ECDSAWithKeyRecovery.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.ECDSAWithKeyRecovery.PublicKey.init(compressedRepresentation:)
		)
	}

	@Test
	func x963Roundtrip() throws {
		try doTest(
			original: K1.ECDSAWithKeyRecovery.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.ECDSAWithKeyRecovery.PublicKey.init(x963Representation:)
		)
	}

	@Test
	func derRoundtrip() throws {
		try doTest(
			original: K1.ECDSAWithKeyRecovery.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.ECDSAWithKeyRecovery.PublicKey.init(derRepresentation:)
		)
	}

	@Test
	func pemRoundtrip() throws {
		try doTest(
			original: K1.ECDSAWithKeyRecovery.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.ECDSAWithKeyRecovery.PublicKey.init(pemRepresentation:)
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
@Suite("K1.KeyAgreement.PublicKey")
struct KeyAgreementPublicKeyEncodingDecodingRoundtripTests {
	@Test
	func pubkey_raw_is_x963_minus_prefix() throws {
		let privateKey = K1.KeyAgreement.PrivateKey()
		let publicKey = privateKey.publicKey
		#expect(publicKey.rawRepresentation.hex == Data(publicKey.x963Representation.dropFirst()).hex)
	}

	@Test
	func rawRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.rawRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(rawRepresentation:)
		)
	}

	@Test
	func compressedRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.compressedRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(compressedRepresentation:)
		)
	}

	@Test
	func x963Roundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.x963Representation,
			deserialize: K1.KeyAgreement.PublicKey.init(x963Representation:)
		)
	}

	@Test
	func derRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.derRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(derRepresentation:)
		)
	}

	@Test
	func pemRoundtrip() throws {
		try doTest(
			original: K1.KeyAgreement.PublicKey(),
			serialize: \.pemRepresentation,
			deserialize: K1.KeyAgreement.PublicKey.init(pemRepresentation:)
		)
	}
}
