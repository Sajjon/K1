import Foundation
import K1
import XCTest

final class ECDSARecoverableSignatureRoundtripTests: XCTestCase {
	func testECDSARecoverable() throws {
		let alice = K1.ECDSAWithKeyRecovery.PrivateKey()
		let message = "Send Bob 3 BTC".data(using: .utf8)!
		let signature = try alice.signature(forUnhashed: message)
		let isSignatureValid = alice.publicKey.isValidSignature(signature, unhashed: message)
		XCTAssertTrue(isSignatureValid, "Signature should be valid.")
	}
}
