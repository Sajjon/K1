import CryptoKit
import Foundation
import K1
import XCTest

final class SchnorrSignatureTests: XCTestCase {
	func testSchnorr() throws {
		let alice = K1.Schnorr.PrivateKey()
		let message = "Send Bob 3 BTC".data(using: .utf8)!
		let signature = try alice.signature(forUnhashed: message)
		let isSignatureValid = alice.publicKey.isValidSignature(signature, unhashed: message)
		XCTAssertTrue(isSignatureValid, "Signature should be valid.")
	}
}
