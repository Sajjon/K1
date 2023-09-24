import K1
import Testing

@Suite("PrivateKey Generation")
struct PrivateKeyGenerationTests {
	@Test
	func testGenerationWorks() throws {
		#expect(throws: Never.self) { _ = try K1.ECDSA.PrivateKey() }
	}

	func testRandom() throws {
		// The probability of two keys being identical is approximately: 1/2^256
		#expect(K1.ECDSA.PrivateKey() != K1.ECDSA.PrivateKey())
	}
}
