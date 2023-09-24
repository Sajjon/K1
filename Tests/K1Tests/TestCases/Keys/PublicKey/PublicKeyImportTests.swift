import Foundation
@testable import K1
import Testing

@Suite("PublicKeyImportTests")
struct PublicKeyImportTests {
	@Test
	func importingPublicKeyWithTooFewBytesThrowsError() throws {
		let raw = try Data(hex: "deadbeef")

		#expect(
			throws: K1.Error.incorrectKeySize
		) {
			_ = try K1.ECDSA.PublicKey(x963Representation: raw)
		}
	}

	@Test
	func importingPublicKeyWithTooManyBytesThrowsError() throws {
		let raw = Data(repeating: 0xDE, count: 66)

		#expect(
			throws: K1.Error.incorrectKeySize
		) {
			_ = try K1.ECDSA.PublicKey(x963Representation: raw)
		}
	}

	@Test
	func importingInvalidUncompressedPublicKeyThrowsError() throws {
		let raw = Data(repeating: 0x04, count: 65)
		#expect(
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyParse)
		) {
			_ = try K1.ECDSA.PublicKey(x963Representation: raw)
		}
	}

	@Test
	func importingInvalidCompressedPublicKeyThrowsError() throws {
		let raw = Data(repeating: 0x03, count: 33)
		#expect(
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyParse)
		) {
			_ = try K1.ECDSA.PublicKey(compressedRepresentation: raw)
		}
	}

	@Test
	func importValidPublicKeyWorks() throws {
		let raw = Data(repeating: 0x02, count: 33)
		let publicKey = try K1.ECDSA.PublicKey(compressedRepresentation: raw)
		#expect(publicKey.compressedRepresentation.hex == "020202020202020202020202020202020202020202020202020202020202020202")
		#expect(publicKey.x963Representation.hex == "040202020202020202020202020202020202020202020202020202020202020202415456f0fc01d66476251cab4525d9db70bfec652b2d8130608675674cde64b2")
	}

	@Test
	func test_compress_pubkey() throws {
		let raw = Data(repeating: 0x02, count: 33)
		let publicKey = try K1.ECDSA.PublicKey(compressedRepresentation: raw)
		#expect(publicKey.compressedRepresentation.hex == "020202020202020202020202020202020202020202020202020202020202020202")
		#expect(publicKey.x963Representation.hex == "040202020202020202020202020202020202020202020202020202020202020202415456f0fc01d66476251cab4525d9db70bfec652b2d8130608675674cde64b2")
	}

	@Test
	func notOnCurve() throws {
		/// Public key from `ecdh_secp256k1_test.json` in Wycheproof
		/// Vector id: 185
		/// With "comment" : "point is not on curve"
		/// DER => raw
		let raw = try Data(hex: "040000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")

		#expect(
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyParse)
		) {
			_ = try K1.ECDSA.PublicKey(x963Representation: raw)
		}
	}
}
