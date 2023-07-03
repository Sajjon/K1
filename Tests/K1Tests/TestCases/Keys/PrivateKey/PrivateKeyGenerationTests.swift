import Foundation
import K1
import XCTest

final class UnsafePrivateKeyGenerationTests: XCTestCase {
	func testGenerationWorks() throws {
		XCTAssertNoThrow(K1.ECDSA.UnsafePrivateKey())
	}

	func testRandom() throws {
		// The probability of two keys being identical is approximately: 1/2^256
		XCTAssertNotEqual(K1.ECDSA.UnsafePrivateKey(), K1.ECDSA.UnsafePrivateKey())
	}
}
