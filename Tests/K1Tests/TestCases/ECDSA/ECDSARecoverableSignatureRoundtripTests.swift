import Foundation
import K1
import Testing

@Suite("ECDSARecoverableSignatureRoundtripTests")
struct ECDSARecoverableSignatureRoundtripTests {
	@Test
	func ecdsaRecoverable() throws {
		let alice = K1.ECDSAWithKeyRecovery.PrivateKey()
		let message = "Send Bob 3 BTC".data(using: .utf8)!
		let signature = try alice.signature(forUnhashed: message)
		let isSignatureValid = alice.publicKey.isValidSignature(signature, unhashed: message)
		#expect(isSignatureValid, "Signature should be valid.")
	}
}
