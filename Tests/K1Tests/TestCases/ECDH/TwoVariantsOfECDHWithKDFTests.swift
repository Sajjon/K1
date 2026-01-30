import CryptoKit
import Foundation
@testable import K1
import XCTest

// MARK: - ECDHX963Suite
private struct ECDHX963Suite: Decodable {
	let origin: String
	let author: String
	let description: String
	let numberOfTests: Int
	let algorithm: String
	let generatedOn: String // data
	let vectors: [Vector]
}

// MARK: - Vector
private struct Vector: Decodable {
	let alicePrivateKey: String
	let bobPrivateKey: String
	let alicePublicKeyUncompressed: String
	let bobPublicKeyUncompressed: String
	let outcomes: [Outcome]

	struct Outcome: Decodable {
		enum ECDHVariant: String, Decodable {
			case asn1X963 = "ASN1X963"
			case libsecp256k1 = "Bitcoin"
		}

		let ecdhVariant: ECDHVariant
		let ecdhSharedKey: String
		let derivedKeys: [DerivedKeys]
		struct DerivedKeys: Decodable {
			/// Used by both `x963` and `HKDF`
			let info: String

			/// `x963` KDF  output
			let x963: String

			/// Salt for `HDKF`
			let salt: String

			let hkdf: String
		}
	}
}

// MARK: - TwoVariantsOfECDHWithKDFTests
final class TwoVariantsOfECDHWithKDFTests: XCTestCase {
	override func setUp() {
		super.setUp()
		continueAfterFailure = false
	}

	func testTwoVariantsOfECDHWithKDF_vectors() throws {
		let fileURL = Bundle.module.url(forResource: "cyon_ecdh_two_variants_with_kdf", withExtension: ".json")
		let data = try Data(contentsOf: fileURL!)
		let suite = try JSONDecoder().decode(ECDHX963Suite.self, from: data)
		try suite.vectors.forEach(doTest)
	}
}

extension TwoVariantsOfECDHWithKDFTests {
	private func doTest(_ vector: Vector) throws {
		let outputByteCount = 32
		let hash = SHA256.self

		let alice = try K1.KeyAgreement.PrivateKey(hex: vector.alicePrivateKey)
		let bob = try K1.KeyAgreement.PrivateKey(hex: vector.bobPrivateKey)
		XCTAssertEqual(alice.publicKey.x963Representation.hex, vector.alicePublicKeyUncompressed)
		XCTAssertEqual(bob.publicKey.x963Representation.hex, vector.bobPublicKeyUncompressed)

		for outcome in vector.outcomes {
			switch outcome.ecdhVariant {
			case .asn1X963:
				let aliceBob = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
				let bobAlice = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)

				XCTAssertEqual(aliceBob, bobAlice)
				aliceBob.withUnsafeBytes {
					XCTAssertEqual(Data($0).hex, outcome.ecdhSharedKey, "Wrong ECDH secret, mismatched expected from vector.")
				}

				for derivedKeys in outcome.derivedKeys {
					let info = try XCTUnwrap(derivedKeys.info.data(using: .utf8))
					let salt = try Data(hex: derivedKeys.salt)
					let x963 = bobAlice.x963DerivedSymmetricKey(using: hash, sharedInfo: info, outputByteCount: outputByteCount)
					x963.withUnsafeBytes {
						XCTAssertEqual(Data($0).hex, derivedKeys.x963, "Wrong X963 KDF result, mismatched expected from vector.")
					}
					let hkdf = bobAlice.hkdfDerivedSymmetricKey(using: hash, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
					hkdf.withUnsafeBytes {
						XCTAssertEqual(Data($0).hex, derivedKeys.hkdf, "Wrong HKDF result, mismatched expected from vector.")
					}
				}

			case .libsecp256k1:
				let aliceBob = try alice.ecdh(with: bob.publicKey)
				let bobAlice = try bob.ecdh(with: alice.publicKey)

				XCTAssertEqual(aliceBob, bobAlice)
				aliceBob.withUnsafeBytes {
					XCTAssertEqual(Data($0).hex, outcome.ecdhSharedKey, "Wrong ECDH secret, mismatched expected from vector.")
				}

				for derivedKeys in outcome.derivedKeys {
					let info = try XCTUnwrap(derivedKeys.info.data(using: .utf8))
					let salt = try Data(hex: derivedKeys.salt)
					let x963 = aliceBob.x963DerivedSymmetricKey(using: hash, sharedInfo: info, outputByteCount: outputByteCount)
					x963.withUnsafeBytes {
						XCTAssertEqual(Data($0).hex, derivedKeys.x963, "Wrong X963 KDF result, mismatched expected from vector.")
					}
					let hkdf = aliceBob.hkdfDerivedSymmetricKey(using: hash, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
					hkdf.withUnsafeBytes {
						XCTAssertEqual(Data($0).hex, derivedKeys.hkdf, "Wrong HKDF result, mismatched expected from vector.")
					}
				}
			}
		}
	}
}
