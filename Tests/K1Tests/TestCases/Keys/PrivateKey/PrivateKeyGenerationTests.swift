import Foundation
import K1
import XCTest

final class PrivateKeyGenerationTests: XCTestCase {
	func testGenerationWorks() throws {
		XCTAssertNoThrow(K1.ECDSA.PrivateKey())
	}

	func testRandom() throws {
		// The probability of two keys being identical is approximately: 1/2^256
		XCTAssertNotEqual(K1.ECDSA.PrivateKey(), K1.ECDSA.PrivateKey())
	}
}
