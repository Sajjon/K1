import Foundation
@testable import K1
import Testing

// MARK: - SchnorrTestGroup
struct SchnorrTestGroup<V: SchnorrTestVector>: Codable {
	let tests: [V]
}

// MARK: - SchnorrTestVector
protocol SchnorrTestVector: Codable {
	var tcId: Int { get }
	var isValid: Bool { get }

	var messageHex: String { get }
	var publicKeyHex: String { get }
	var signatureCompact: String { get }

	var comment: String? { get }
	var flags: [String]? { get }
}

extension SchnorrTestVector {
	var comment: String? { nil }
	var flags: [String]? { nil }
}

// MARK: - SchnorrTestVerifyVector
struct SchnorrTestVerifyVector: SchnorrTestVector {
	let isValid: Bool
	let messageHex: String
	let tcId: Int
	let publicKeyHex: String
	let signatureCompact: String
	let comment: String?
	let flags: [String]?
}

// MARK: - SchnorrTestSignVector
struct SchnorrTestSignVector: SchnorrTestVector {
	let isValid: Bool
	let messageHex: String
	let auxDataHex: String
	let tcId: Int
	let publicKeyHex: String
	let privateKeyHex: String
	let signatureCompact: String
	let comment: String?
}

// MARK: - SchnorrSignatureBitcoinCoreTests
@Suite("Schnorr Signature BitcoinCore")
struct SchnorrSignatureBitcoinCoreTests {
	@Test
	func schnorrSignBitcoinVectors() throws {
		let _: TestResult = try testSuite(
			/* https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv */
			jsonName: "bip340_schnorr_sign",
			testFunction: { (group: SchnorrTestGroup<SchnorrTestSignVector>) in
				var numberOfTestsRun = 0
				try group.tests.forEach(doTestSchnorrSign)
				numberOfTestsRun += 1
				return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
			}
		)
	}

	@Test
	func schnorrVerifyBitcoinVectors() throws {
		let _: TestResult =
			try testSuite(
				/* https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv */
				jsonName: "bip340_schnorr_verify",
				testFunction: { (group: SchnorrTestGroup<SchnorrTestVerifyVector>) in
					var numberOfTestsRun = 0
					try group.tests.forEach(doTestSchnorrVerify)
					numberOfTestsRun += 1
					return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
				}
			)
	}
}

private extension SchnorrSignatureBitcoinCoreTests {
	func doTestSchnorrSign(vector: SchnorrTestSignVector) throws {
		let privateKey = try K1.Schnorr.PrivateKey(
			rawRepresentation: Data(hex: vector.privateKeyHex)
		)

		let publicKey = privateKey.publicKey
		let expectedPublicKey = try K1.Schnorr.PublicKey(compressedRepresentation: Data(hex: vector.publicKeyHex))
		#expect(publicKey == expectedPublicKey)

		#expect(
			publicKey.compressedRepresentation ==
				expectedPublicKey.compressedRepresentation
		)

		let message = try Data(hex: vector.messageHex)
		let signature = try privateKey.signature(
			for: message,
			options: .init(auxiliaryRandomData: .specific(.init(aux: Data(hex: vector.auxDataHex))))
		)

		let expectedSig = try K1.Schnorr.Signature(rawRepresentation: Data(hex: vector.signatureCompact))

		#expect(signature.rawRepresentation.hex == vector.signatureCompact)

		#expect(
			publicKey.isValidSignature(expectedSig, hashed: message) ==
				vector.isValid
		)
	}

	func doTestSchnorrVerify(vector: SchnorrTestVector) throws {
		func parsePublicKey() throws -> K1.Schnorr.PublicKey {
			try .init(compressedRepresentation: Data(hex: vector.publicKeyHex))
		}
		guard !vector.invalidPublicKey else {
			#expect(throws: K1.Error.underlyingLibsecp256k1Error(.publicKeyParse)) {
				_ = try parsePublicKey()
			}
			return
		}
		let publicKey = try parsePublicKey()

		let signature = try K1.Schnorr.Signature(rawRepresentation: Data(hex: vector.signatureCompact))

		let validSignature = try publicKey.isValidSignature(
			signature, hashed: Data(hex: vector.messageHex)
		)

		#expect(validSignature == vector.isValid)
	}
}

extension SchnorrTestVector {
	func hasFlag(_ flag: String) -> Bool {
		guard let flags = flags else { return false }
		return flags.contains(flag)
	}

	var invalidPublicKey: Bool {
		hasFlag("InvalidPublicKey")
	}
}
