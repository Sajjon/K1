import Foundation
@testable import K1
import XCTest

// MARK: - UnsafePrivateKeyEncodingTests
final class UnsafePrivateKeyEncodingTests: XCTestCase {
	func testRawRoundtrip() throws {
		try doTest(
			serialize: \.rawRepresentation,
			deserialize: K1.ECDSA.UnsafePrivateKey.init(rawRepresentation:)
		)
	}

	func testx963Roundtrip() throws {
		try doTest(
			serialize: \.x963Representation,
			deserialize: K1.ECDSA.UnsafePrivateKey.init(x963Representation:)
		)
	}

	func testDERRoundtrip() throws {
		try doTest(
			serialize: \.derRepresentation,
			deserialize: K1.ECDSA.UnsafePrivateKey.init(derRepresentation:)
		)
	}

	func testPEMRoundtrip() throws {
		try doTest(
			serialize: \.pemRepresentation,
			deserialize: K1.ECDSA.UnsafePrivateKey.init(pemRepresentation:)
		)
	}
}

private extension UnsafePrivateKeyEncodingTests {
	func doTest<Enc: Equatable>(
		serialize: KeyPath<K1.ECDSA.UnsafePrivateKey, Enc>,
		deserialize: (Enc) throws -> K1.ECDSA.UnsafePrivateKey
	) throws {
		try doTestSerializationRoundtrip(
			original: K1.ECDSA.UnsafePrivateKey(),
			serialize: serialize,
			deserialize: deserialize
		)
	}
}
