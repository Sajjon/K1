import Foundation
@testable import K1
import Testing

@Suite("PrivateKeyImportTests")
struct PrivateKeyImportTests {
	@Test
	func importingPrivateKeyWithTooFewBytesThrowsError() throws {
		let raw = try Data(hex: "deadbeef")
		#expect(
			throws: K1.Error.incorrectKeySize
		) {
			_ = try K1.ECDSA.PrivateKey(rawRepresentation: raw)
		}
	}

	@Test
	func importingPrivateKeyWithTooManyBytesThrowsError() throws {
		let raw = Data(repeating: 0xBA, count: 33)
		#expect(
			throws: K1.Error.incorrectKeySize
		) {
			_ = try K1.ECDSA.PrivateKey(rawRepresentation: raw)
		}
	}

	@Test
	func importingPrivateKeyZeroThrowsError() throws {
		let raw = Data(repeating: 0x00, count: 32)
		#expect(
			throws: K1.Error.invalidKey
		) {
			_ = try K1.ECDSA.PrivateKey(rawRepresentation: raw)
		}
	}

	@Test
	func importingPrivateKeyCurveOrderThrowsError() throws {
		let raw = try Data(hex: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")

		#expect(
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyCreate)
		) {
			_ = try K1.ECDSA.PrivateKey(rawRepresentation: raw)
		}
	}

	@Test
	func importingPrivateKeyLargerThanCurveOrderThrowsError() throws {
		let raw = Data(repeating: 0xFF, count: 32)

		#expect(
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyCreate)
		) {
			_ = try K1.ECDSA.PrivateKey(rawRepresentation: raw)
		}
	}

	@Test
	func publicKeyOfImportedPrivateKey1() throws {
		let privateKeyRaw = try Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")
		let privateKey = try K1.ECDSA.PrivateKey(rawRepresentation: privateKeyRaw)
		// Easily verified by: https://bitaddress.org/
		// Pretty well known key pair
		let expectedPublicKey = try K1.ECDSA.PublicKey(x963Representation: Data(hex: "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))

		#expect(privateKey.publicKey == expectedPublicKey)
	}
}
