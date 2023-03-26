import CryptoKit
import Foundation
@testable import K1
import XCTest

// MARK: - ECDSA_Wycheproof_IEEE_P1364_RS_EncodedSignaturesTests
final class ECDSA_Wycheproof_IEEE_P1364_RS_EncodedSignaturesTests: XCTestCase {
	func testWycheProofSecp256k1_P1364_RS() throws {
		let _: TestResult =
			try testSuite(
				/* https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp256k1_sha256_test.json */
				jsonName: "wycheproof_ecdsa_verify_p1363",
				testFunction: { (group: ECDSAWycheTestGroup<SignatureWycheproofP1364TestVector>) in
					try doTestGroup(
						group: group,
						signatureValidationMode: .init(malleabilityStrictness: .accepted),
						hashFunction: SHA256.self,
						skipIfContainsFlags: .init(["MissingZero", "BER", "SigSize"]),
						skipIfContainsComment: ["r too large"]
					)
				}
			)
	}
}

// MARK: - SignatureWycheproofP1364TestVector
private struct SignatureWycheproofP1364TestVector: WycheproofTestVector {
	typealias MessageDigest = SHA256.Digest
	typealias Signature = K1.ECDSA.NonRecoverable.Signature

	let comment: String
	let msg: String
	let sig: String
	let result: String
	let flags: [String]
	let tcId: Int

	func messageDigest() throws -> MessageDigest {
		let msg = try Data(hex: msg)
		return SHA256.hash(data: msg)
	}

	func expectedSignature() throws -> Signature {
		let raw = try Data(hex: sig)
		let signature = try Signature(rawRepresentation: raw)
		if self.result == "valid" {
			XCTAssertEqual(sig, signature.rawRepresentation.hex)
		}
		return signature
	}
}
