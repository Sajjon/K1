import Foundation
import K1
import XCTest

final class PerformanceTests: XCTestCase {
	func testPerformance() {
		let message = [UInt8](repeating: 0xAB, count: 32)
		measure {
			do {
				for _ in 0 ..< 10 {
					let schnorrUnsafePrivateKey = K1.Schnorr.UnsafePrivateKey()
					let schnorrPublicKey = schnorrUnsafePrivateKey.publicKey

					try XCTAssertEqual(
						K1.Schnorr.PublicKey(compressedRepresentation: schnorrPublicKey.compressedRepresentation),
						schnorrPublicKey
					)
					try XCTAssertEqual(
						K1.Schnorr.PublicKey(x963Representation: schnorrPublicKey.x963Representation),
						schnorrPublicKey
					)

					let ecdsaUnsafePrivateKey = K1.ECDSAWithKeyRecovery.UnsafePrivateKey()
					let ecdsaPublicKey = ecdsaUnsafePrivateKey.publicKey

					try XCTAssertEqual(
						K1.ECDSAWithKeyRecovery.PublicKey(compressedRepresentation: ecdsaPublicKey.compressedRepresentation),
						ecdsaPublicKey
					)
					try XCTAssertEqual(
						K1.ECDSAWithKeyRecovery.PublicKey(x963Representation: ecdsaPublicKey.x963Representation),
						ecdsaPublicKey
					)

					let ecdsa = try ecdsaUnsafePrivateKey.signature(for: message)
					XCTAssertTrue(
						ecdsaPublicKey.isValidSignature(
							ecdsa,
							hashed: message
						)
					)
					try XCTAssertEqual(
						K1.ECDSAWithKeyRecovery.Signature(compact: ecdsa.compact()),
						ecdsa
					)
					try XCTAssertEqual(
						K1.ECDSA.Signature(rawRepresentation: ecdsa.nonRecoverable().rawRepresentation),
						ecdsa.nonRecoverable()
					)
					try XCTAssertEqual(
						K1.ECDSA.Signature(derRepresentation: ecdsa.nonRecoverable().derRepresentation),
						ecdsa.nonRecoverable()
					)

					let schnorr = try schnorrUnsafePrivateKey.signature(for: message)
					XCTAssertTrue(
						schnorrPublicKey.isValidSignature(
							schnorr,
							hashed: message
						)
					)
					try XCTAssertEqual(
						K1.Schnorr.Signature(rawRepresentation: schnorr.rawRepresentation),
						schnorr
					)

					let aliceUnsafePrivateKey = try K1.KeyAgreement.UnsafePrivateKey(x963Representation: ecdsaUnsafePrivateKey.x963Representation)
					let alicePublicKey = aliceUnsafePrivateKey.publicKey
					let bobUnsafePrivateKey = K1.KeyAgreement.UnsafePrivateKey()
					let bobPublicKey = bobUnsafePrivateKey.publicKey

					var ab = try aliceUnsafePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
					var ba = try bobUnsafePrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)
					XCTAssertEqual(ab, ba)
					ab = try aliceUnsafePrivateKey.ecdh(with: bobPublicKey)
					ba = try bobUnsafePrivateKey.ecdh(with: alicePublicKey)
					XCTAssertEqual(ab, ba)
				}
			} catch {
				XCTFail("abort")
			}
		}
	}
}
