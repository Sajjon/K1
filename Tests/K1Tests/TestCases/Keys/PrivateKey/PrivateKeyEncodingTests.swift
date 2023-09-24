import Foundation
@testable import K1
import Testing

// MARK: - PrivateKeyEncodingTests
@Suite("PrivateKeyEncodingTests")
struct PrivateKeyEncodingTests {
	@Test
	func rawRoundtrip() throws {
		try doTest(
			serialize: \.rawRepresentation,
			deserialize: K1.ECDSA.PrivateKey.init(rawRepresentation:)
		)
	}

	@Test
	func x963Roundtrip() throws {
		try doTest(
			serialize: \.x963Representation,
			deserialize: K1.ECDSA.PrivateKey.init(x963Representation:)
		)
	}

	@Test
	func derRoundtrip() throws {
		try doTest(
			serialize: \.derRepresentation,
			deserialize: K1.ECDSA.PrivateKey.init(derRepresentation:)
		)
	}

	@Test
	func pemRoundtrip() throws {
		try doTest(
			serialize: \.pemRepresentation,
			deserialize: K1.ECDSA.PrivateKey.init(pemRepresentation:)
		)
	}
}

private extension PrivateKeyEncodingTests {
	func doTest<Enc: Equatable>(
		serialize: KeyPath<K1.ECDSA.PrivateKey, Enc>,
		deserialize: (Enc) throws -> K1.ECDSA.PrivateKey
	) throws {
		try doTestSerializationRoundtrip(
			original: K1.ECDSA.PrivateKey(),
			serialize: serialize,
			deserialize: deserialize
		)
	}
}
