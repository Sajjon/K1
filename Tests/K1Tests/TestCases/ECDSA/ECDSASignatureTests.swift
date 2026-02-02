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

	@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
	func test_ecdsa_from_inline_array() throws {
		let data = try Data(hex: "74b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8")
		let inlineArray = try InlineArray<64, UInt8>(data: data)
		let signature = try K1.ECDSA.Signature(rawRepresentation: inlineArray)
		XCTAssertEqual(signature.rawRepresentation, data)

	}

}
