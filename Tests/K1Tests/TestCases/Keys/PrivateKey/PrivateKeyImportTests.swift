import Foundation
@testable import K1
import XCTest

// MARK: - UnsafePrivateKeyImportTests
final class UnsafePrivateKeyImportTests: XCTestCase {
	func testAssertImportingUnsafePrivateKeyWithTooFewBytesThrowsError() throws {
		let raw = try Data(hex: "deadbeef")
		try assert(
			K1.ECDSA.UnsafePrivateKey(rawRepresentation: raw),
			throws: K1.Error.incorrectKeySize
		)
	}

	func testAssertImportingUnsafePrivateKeyWithTooManyBytesThrowsError() throws {
		let raw = Data(repeating: 0xBA, count: 33)
		try assert(
			K1.ECDSA.UnsafePrivateKey(rawRepresentation: raw),
			throws: K1.Error.incorrectKeySize
		)
	}

	func testAssertImportingUnsafePrivateKeyZeroThrowsError() throws {
		let raw = Data(repeating: 0x00, count: 32)
		try assert(
			K1.ECDSA.UnsafePrivateKey(rawRepresentation: raw),
			throws: K1.Error.invalidKey
		)
	}

	func testAssertImportingUnsafePrivateKeyCurveOrderThrowsError() throws {
		let raw = try Data(hex: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
		try assert(
			K1.ECDSA.UnsafePrivateKey(rawRepresentation: raw),
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyCreate)
		)
	}

	func testAssertImportingUnsafePrivateKeyLargerThanCurveOrderThrowsError() throws {
		let raw = Data(repeating: 0xFF, count: 32)
		try assert(
			K1.ECDSA.UnsafePrivateKey(rawRepresentation: raw),
			throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyCreate)
		)
	}

	func testAssertPublicKeyOfImportedUnsafePrivateKey1() throws {
		let privateKeyRaw = try Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")
		let privateKey = try K1.ECDSA.UnsafePrivateKey(rawRepresentation: privateKeyRaw)
		// Easily verified by: https://bitaddress.org/
		// Pretty well known key pair
		let expectedPublicKey = try K1.ECDSA.PublicKey(x963Representation: Data(hex: "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
		XCTAssertEqual(privateKey.publicKey, expectedPublicKey)
	}
}
