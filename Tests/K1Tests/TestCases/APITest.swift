import CryptoKit
import Foundation
import K1 // not `@testable import`!!
import XCTest

final class APITest: XCTestCase {
	func testECDSA() throws {
		let privateKey: K1.ECDSA.PrivateKey = .init()
		let publicKey: K1.ECDSA.PublicKey = privateKey.publicKey
		let hashed = Data(SHA256.hash(data: Data("Hey Bob!".utf8)))
		let signature = try privateKey.signature(for: hashed)
		let isValid = publicKey.isValidSignature(signature, hashed: hashed)
		XCTAssertTrue(isValid)

		// Wrong public key
		XCTAssertFalse(
			type(of: privateKey).init().publicKey.isValidSignature(signature, hashed: hashed),
			"When wrong public key is used to validate signature, validation should fail."
		)

		// Modify message
		XCTAssertFalse(
			publicKey.isValidSignature(signature, hashed: Data(hashed.reversed())),
			"When the wrong message is used during validation of signature, validation should fail."
		)

		// Modify signature
		try XCTAssertFalse(
			publicKey.isValidSignature(.init(rawRepresentation: signature.rawRepresentation.reversed()), hashed: hashed),
			"Tampered signatures should fail validation."
		)
	}

	func testECDSAWithRecovery() throws {
		let privateKey: K1.ECDSA.KeyRecovery.PrivateKey = .init()
		let publicKey: K1.ECDSA.KeyRecovery.PublicKey = privateKey.publicKey
		let hashed = Data(SHA256.hash(data: Data("Hey Bob!".utf8)))
		let signature = try privateKey.signature(for: hashed)
		let isValid = publicKey.isValidSignature(signature, hashed: hashed)
		XCTAssertTrue(isValid)

		// Wrong public key
		XCTAssertFalse(
			type(of: privateKey).init().publicKey.isValidSignature(signature, hashed: hashed),
			"When wrong public key is used to validate signature, validation should fail."
		)

		// Modify message
		XCTAssertFalse(
			publicKey.isValidSignature(signature, hashed: Data(hashed.reversed())),
			"When the wrong message is used during validation of signature, validation should fail."
		)

		// Modify signature
		let modifiedSignature: K1.ECDSA.KeyRecovery.Signature = try {
			let compact = try signature.compact()
			let rs = compact.compact
			let v = compact.recoveryID
			return try K1.ECDSA.KeyRecovery.Signature(compact: .init(compact: .init(rs.reversed()), recoveryID: v))
		}()
		XCTAssertFalse(
			publicKey.isValidSignature(modifiedSignature, hashed: hashed),
			"Tampered signatures should fail validation."
		)
	}

	func testSchnorr() throws {
		let privateKey: K1.Schnorr.PrivateKey = .init()
		let publicKey: K1.Schnorr.PublicKey = privateKey.publicKey
		let hashed = Data(SHA256.hash(data: Data("Hey Bob!".utf8)))
		let signature = try privateKey.signature(for: hashed)
		let isValid = publicKey.isValidSignature(signature, hashed: hashed)
		XCTAssertTrue(isValid)

		// Wrong public key
		XCTAssertFalse(
			type(of: privateKey).init().publicKey.isValidSignature(signature, hashed: hashed),
			"When wrong public key is used to validate signature, validation should fail."
		)

		// Modify message
		XCTAssertFalse(
			publicKey.isValidSignature(signature, hashed: Data(hashed.reversed())),
			"When the wrong message is used during validation of signature, validation should fail."
		)

		// Modify signature
		try XCTAssertFalse(
			publicKey.isValidSignature(.init(rawRepresentation: signature.rawRepresentation.reversed()), hashed: hashed),
			"Tampered signatures should fail validation."
		)
	}

	func testECDH() throws {
		let alice = K1.KeyAgreement.PrivateKey()
		let bob = K1.KeyAgreement.PrivateKey()
		let ab = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
		let ba = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)
		XCTAssertEqual(ab, ba)
	}
}
