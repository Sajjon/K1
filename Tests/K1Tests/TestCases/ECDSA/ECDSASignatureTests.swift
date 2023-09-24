import CryptoKit
import Foundation
@testable import K1
import Testing

@Suite("ECDSASignatureTests")
struct ECDSASignatureTests {
	@Test
	func ecdasDeterministic() throws {
		let alice = K1.ECDSA.PrivateKey()
		let message = "Send Bob 3 BTC".data(using: .utf8)!

		let signature = try alice.signature(forUnhashed: message)
		let isSignatureValid = alice.publicKey.isValidSignature(signature, unhashed: message)
		#expect(isSignatureValid, "Signature should be valid.")
	}

	@Test
	func ecdsaRandom() throws {
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
			#expect(isSignatureValid, "Signature should be valid.")
			#expect(signatures.count == i)
			signatures.insert(signature)
		}
	}
}
