import CryptoKit
import Foundation
import K1 // not `@testable import`!!
import Testing

@Suite("API")
struct APITest {
	@Test
	func ecdsa() throws {
		let privateKey: K1.ECDSA.PrivateKey = .init()
		let publicKey: K1.ECDSA.PublicKey = privateKey.publicKey
		let hashed = Data(SHA256.hash(data: Data("Hey Bob!".utf8)))
		let signature = try privateKey.signature(for: hashed)

		#expect(publicKey.isValidSignature(signature, hashed: hashed))

		// Wrong public key
		#expect(
			!type(of: privateKey).init().publicKey.isValidSignature(signature, hashed: hashed),
			"When wrong public key is used to validate signature, validation should fail."
		)

		// Modify message
		#expect(
			!publicKey.isValidSignature(signature, hashed: Data(hashed.reversed())),
			"When the wrong message is used during validation of signature, validation should fail."
		)

		// Modify signature
		try #expect(
			!publicKey.isValidSignature(.init(rawRepresentation: signature.rawRepresentation.reversed()), hashed: hashed),
			"Tampered signatures should fail validation."
		)
	}

	@Test
	func ecdsaWithRecovery() throws {
		let privateKey: K1.ECDSAWithKeyRecovery.PrivateKey = .init()
		let publicKey: K1.ECDSAWithKeyRecovery.PublicKey = privateKey.publicKey
		let hashed = Data(SHA256.hash(data: Data("Hey Bob!".utf8)))
		let signature = try privateKey.signature(for: hashed)
		let isValid = publicKey.isValidSignature(signature, hashed: hashed)
		#expect(isValid)

		// Wrong public key
		#expect(
			!type(of: privateKey).init().publicKey.isValidSignature(signature, hashed: hashed),
			"When wrong public key is used to validate signature, validation should fail."
		)

		// Modify message
		#expect(
			!publicKey.isValidSignature(signature, hashed: Data(hashed.reversed())),
			"When the wrong message is used during validation of signature, validation should fail."
		)

		// Modify signature
		let modifiedSignature: K1.ECDSAWithKeyRecovery.Signature = try {
			let compact = try signature.compact()
			let rs = compact.compact
			let v = compact.recoveryID
			return try K1.ECDSAWithKeyRecovery.Signature(compact: .init(compact: .init(rs.reversed()), recoveryID: v))
		}()

		#expect(
			!publicKey.isValidSignature(modifiedSignature, hashed: hashed),
			"Tampered signatures should fail validation."
		)
	}

	@Test
	func schnorr() throws {
		let privateKey: K1.Schnorr.PrivateKey = .init()
		let publicKey: K1.Schnorr.PublicKey = privateKey.publicKey
		let hashed = Data(SHA256.hash(data: Data("Hey Bob!".utf8)))
		let signature = try privateKey.signature(for: hashed)
		let isValid = publicKey.isValidSignature(signature, hashed: hashed)
		#expect(isValid)

		// Wrong public key
		#expect(
			!type(of: privateKey).init().publicKey.isValidSignature(signature, hashed: hashed),
			"When wrong public key is used to validate signature, validation should fail."
		)

		// Modify message
		#expect(
			!publicKey.isValidSignature(signature, hashed: Data(hashed.reversed())),
			"When the wrong message is used during validation of signature, validation should fail."
		)

		// Modify signature
		try #expect(
			!publicKey.isValidSignature(.init(rawRepresentation: signature.rawRepresentation.reversed()), hashed: hashed),
			"Tampered signatures should fail validation."
		)
	}

	@Test
	func eCDH() throws {
		let alice = K1.KeyAgreement.PrivateKey()
		let bob = K1.KeyAgreement.PrivateKey()
		let ab = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
		let ba = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)
		#expect(ab == ba)
	}
}
