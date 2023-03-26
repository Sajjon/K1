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

	func testSchnorrAssertRandomAuxIsUsedByDefault() throws {
		func doTest(aux: K1.Schnorr.SigningOptions.AuxiliaryRandomData, expectUnique: Bool) throws {
			let count = 100
			var signatures = Set<K1.Schnorr.Signature>()
			let alice = K1.Schnorr.PrivateKey()
			let message = "Send Bob 3 BTC".data(using: .utf8)!
			let hashed = SHA256.hash(data: message)
			for _ in 0 ..< count {
				let signature = try alice.signature(for: hashed, options: .init(auxiliaryRandomData: aux))
				XCTAssertTrue(alice.publicKey.isValidSignature(signature, digest: hashed))
				signatures.insert(signature)
			}
			if expectUnique {
				XCTAssertEqual(signatures.count, count)
			} else {
				XCTAssertEqual(signatures.count, 1)
			}
		}

		try doTest(aux: .default, expectUnique: true)
		try doTest(aux: .random, expectUnique: true)
		try doTest(aux: .none, expectUnique: false)
	}
}
