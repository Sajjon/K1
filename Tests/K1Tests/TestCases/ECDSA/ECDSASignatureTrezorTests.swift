import CryptoKit
@testable import K1
import XCTest

// MARK: - ECDSASignatureTrezorsTests
/// Test vectors from [trezor][trezor], signature data from [oleganza][oleganza]
///
/// More vectors can be founds on bitcointalk forum, [here][bitcointalk1] and [here][bitcointalk2] (unreliable?)
///
/// [trezor]: https://github.com/trezor/trezor-crypto/blob/957b8129bded180c8ac3106e61ff79a1a3df8893/tests/test_check.c#L1959-L1965
/// [oleganza]: https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoinTestsOSX/BTCKeyTests.swift
/// [bitcointalk1]: https://bitcointalk.org/index.php?topic=285142.msg3300992#msg3300992
/// [bitcointalk2]: https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
final class ECDSASignatureTrezorsTests: XCTestCase {
	func testTrezorSecp256k1() throws {
		let _: TestResult = try testSuite(
			jsonName: "trezor_ecdsa_sign_rfc6979",
			testFunction: { group in
				try doTestGroup(
					group: group
				)
			}
		)
	}
}

private extension XCTestCase {
	func doTestGroup(
		group: ECDSATestGroup<SignatureTrezorTestVector>,
		file: StaticString = #file,
		line: UInt = #line
	) throws -> ResultOfTestGroup {
		var numberOfTestsRun = 0
		for vector in group.tests {
			let privateKey = try K1.ECDSA.PrivateKey(rawRepresentation: Data(hex: vector.privateKey))
			let publicKey: K1.ECDSA.PublicKey = privateKey.publicKey

			let expectedSignature = try vector.expectedSignature()
			let messageDigest = try vector.messageDigest()
			XCTAssertTrue(publicKey.isValidSignature(expectedSignature, digest: messageDigest))

			let signatureFromMessage = try privateKey.signature(for: messageDigest)
			XCTAssertEqual(signatureFromMessage, expectedSignature)

			let signatureRandom = try privateKey.signature(
				for: messageDigest,
				options: .init(nonceFunction: .random)
			)

			XCTAssertNotEqual(signatureRandom, expectedSignature)
			XCTAssertTrue(publicKey.isValidSignature(signatureRandom, digest: messageDigest))

			let privateKeyRecoverable = try K1.ECDSA.KeyRecovery.PrivateKey(rawRepresentation: privateKey.rawRepresentation)
			let signatureRecoverableFromMessage = try privateKeyRecoverable.signature(for: messageDigest)
			try XCTAssertEqual(signatureRecoverableFromMessage.nonRecoverable(), expectedSignature)
			let recid = try signatureRecoverableFromMessage.compact().recoveryID

			XCTAssertEqual(
				signatureRecoverableFromMessage.internalRepresentation.hex,
				expectedSignature.internalRepresentation.hex + "\(Data([UInt8(recid.rawValue)]).hex)"
			)

			try XCTAssertEqual(
				signatureRecoverableFromMessage.compact().serialize(format: .rsv).hex,
				expectedSignature.rawRepresentation.hex + "\(Data([UInt8(recid.rawValue)]).hex)"
			)

			numberOfTestsRun += 1
		}
		return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
	}
}

// MARK: - SignatureTrezorTestVector
private struct SignatureTrezorTestVector: SignatureTestVector {
	typealias MessageDigest = SHA256.Digest
	typealias Signature = K1.ECDSA.Signature

	let msg: String
	let privateKey: String
	let expected: Expected
	struct Expected: Codable {
		let k: String
		let r: String
		let s: String
		let der: String
	}

	let tcId: Int

	func messageDigest() throws -> MessageDigest {
		let messageToHash = msg.data(using: .utf8)!
		return SHA256.hash(data: messageToHash)
	}

	func expectedSignature() throws -> Signature {
		let derData = try Data(hex: expected.der)
		let signature = try K1.ECDSA.Signature(derRepresentation: derData)
		XCTAssertEqual(signature.derRepresentation.hex, expected.der)
		XCTAssertEqual(
			signature.rawRepresentation.hex,
			[
				expected.r,
				expected.s,
			].joined(separator: "")
		)

		try XCTAssertEqual(
			K1.ECDSA.Signature(rawRepresentation: Data(hex: expected.r + expected.s)),
			signature
		)

		return signature
	}
}
