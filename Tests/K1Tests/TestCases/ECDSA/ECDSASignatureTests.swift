import CryptoKit
import Foundation
@testable import K1
import XCTest

final class ECDSASignatureTests: XCTestCase {
	func testECDSADeterministic() throws {
		let alice = K1.ECDSA.PrivateKey()
		let message = "Send Bob 3 BTC".data(using: .utf8)!

		let signature = try alice.signature(forUnhashed: message)
		let isSignatureValid = alice.publicKey.isValidSignature(signature, unhashed: message)
		XCTAssertTrue(isSignatureValid, "Signature should be valid.")
	}

	func testECDSARandom() throws {
		continueAfterFailure = false
		let alice = K1.ECDSA.PrivateKey()
		let message = "Send Bob 3 BTC".data(using: .utf8)!

		let requestedNumberOfSignatures = 1000
		var signatures = Set<K1.ECDSA.Signature>()

		for i in 0 ..< requestedNumberOfSignatures {
			let signature = try alice.signature(
				forUnhashed: message,
				options: .init(nonceFunction: .random)
			)
			let isSignatureValid = alice.publicKey.isValidSignature(
				signature,
				unhashed: message
			)
			XCTAssertTrue(isSignatureValid, "Signature should be valid.")
			XCTAssertEqual(signatures.count, i)
			signatures.insert(signature)
		}
	}
}
