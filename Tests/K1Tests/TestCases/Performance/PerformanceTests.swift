import Foundation
import K1
@testable @_spi(ExperimentalTestRunning) @_spi(ExperimentalEventHandling) @_spi(ExperimentalParameterizedTesting) import Testing

// MARK: - PerformanceTests
@Suite("Performance")
struct PerformanceTests {
	@Test
	func performance() {
		let timeAwaited = Test.Clock().measure {
			do {
				for _ in 0 ..< 100 {
					try doTest()
				}
			} catch {
				Issue.record("Test failed with error: \(error)")
			}
		}
		#expect(timeAwaited < .seconds(1)) // ca 350 ms on an M1 Macbook Pro
	}
}

private func doTest() throws {
	let message = [UInt8](repeating: 0xAB, count: 32)

	let schnorrPrivateKey = K1.Schnorr.PrivateKey()
	let schnorrPublicKey = schnorrPrivateKey.publicKey

	try #expect(
		K1.Schnorr.PublicKey(compressedRepresentation: schnorrPublicKey.compressedRepresentation) ==
			schnorrPublicKey
	)
	try #expect(
		K1.Schnorr.PublicKey(x963Representation: schnorrPublicKey.x963Representation) ==
			schnorrPublicKey
	)

	let ecdsaPrivateKey = K1.ECDSAWithKeyRecovery.PrivateKey()
	let ecdsaPublicKey = ecdsaPrivateKey.publicKey

	try #expect(
		K1.ECDSAWithKeyRecovery.PublicKey(compressedRepresentation: ecdsaPublicKey.compressedRepresentation) ==
			ecdsaPublicKey
	)
	try #expect(
		K1.ECDSAWithKeyRecovery.PublicKey(x963Representation: ecdsaPublicKey.x963Representation) ==
			ecdsaPublicKey
	)

	let ecdsa = try ecdsaPrivateKey.signature(for: message)
	#expect(
		ecdsaPublicKey.isValidSignature(
			ecdsa,
			hashed: message
		)
	)

	try #expect(
		K1.ECDSAWithKeyRecovery.Signature(compact: ecdsa.compact()) ==
			ecdsa
	)

	#expecttry (
		K1.ECDSA.Signature(rawRepresentation: ecdsa.nonRecoverable().rawRepresentation) ==
			ecdsa.nonRecoverable()
	)

	#expecttry (
		K1.ECDSA.Signature(derRepresentation: ecdsa.nonRecoverable().derRepresentation) ==
			ecdsa.nonRecoverable()
	)

	let schnorr = try schnorrPrivateKey.signature(for: message)

	#expect(
		schnorrPublicKey.isValidSignature(
			schnorr,
			hashed: message
		)
	)

	try #expect(
		K1.Schnorr.Signature(rawRepresentation: schnorr.rawRepresentation) ==
			schnorr
	)

	let alicePrivateKey = try K1.KeyAgreement.PrivateKey(x963Representation: ecdsaPrivateKey.x963Representation)
	let alicePublicKey = alicePrivateKey.publicKey
	let bobPrivateKey = K1.KeyAgreement.PrivateKey()
	let bobPublicKey = bobPrivateKey.publicKey

	var ab = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
	var ba = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)
	#expect(ab == ba)
	ab = try alicePrivateKey.ecdh(with: bobPublicKey)
	ba = try bobPrivateKey.ecdh(with: alicePublicKey)
	#expect(ab == ba)
}
