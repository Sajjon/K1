import Foundation
@testable import K1
import XCTest

// MARK: - ECDSASignaturePublicKeyRecoveryTests
/// Test vectors:
/// https://gist.github.com/webmaster128/130b628d83621a33579751846699ed15
final class ECDSASignaturePublicKeyRecoveryTests: XCTestCase {
	override func setUp() {
		super.setUp()
		continueAfterFailure = false
	}

	func test_recovery_test_vectors() throws {
		let _: TestResult = try testSuite(
			jsonName: "warta_cyon_publickey_recovery",
			testFunction: { (group: RecoveryTestGroup) in
				try doTestGroup(group: group)
			}
		)
	}

	func test_conversionRoundtrips() throws {
		let recoverySignatureHex = "acf9e195e094f2f40eb619b9878817ff951b9b11fac37cf0d7290098bbefb574f8606281a2231a3fc781045f2ea4df086936263bbfa8d15ca17fe70e0c3d6e5601"
		let recoverableSigRaw = try Data(hex: recoverySignatureHex)
		let recoverableSig = try K1.ECDSA.KeyRecovery.Signature(internalRepresentation: recoverableSigRaw)
		XCTAssertEqual(recoverableSig.internalRepresentation.hex, recoverySignatureHex)

		let compactRSV = "74b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f801"
		try XCTAssertEqual(recoverableSig.compact().serialize(format: .rsv).hex, compactRSV)
		let compactVRS = "0174b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8"
		try XCTAssertEqual(recoverableSig.compact().serialize(format: .vrs).hex, compactVRS)

		try XCTAssertEqual(
			recoverableSig.internalRepresentation.hex,
			K1.ECDSA.KeyRecovery.Signature(compact: .init(rawRepresentation: Data(hex: compactVRS), format: .vrs)).internalRepresentation.hex
		)

		let compactRecoverableSig = try recoverableSig.compact()

		let compactRecoverableSigRSHex = "74b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8"
		let recid = try K1.ECDSA.KeyRecovery.Signature.RecoveryID(recid: 1)
		XCTAssertEqual(compactRecoverableSig.compact.hex, compactRecoverableSigRSHex)
		XCTAssertEqual(compactRecoverableSig.recoveryID, recid)

		let compactRecoverableSigRS = try Data(hex: compactRecoverableSigRSHex)
		try XCTAssertEqual(K1.ECDSA.KeyRecovery.Signature(compact: .init(compact: compactRecoverableSigRS, recoveryID: recid)), K1.ECDSA.KeyRecovery.Signature(compact: compactRecoverableSig))
		try XCTAssertEqual(K1.ECDSA.KeyRecovery.Signature.Compact(compact: compactRecoverableSigRS, recoveryID: recid), compactRecoverableSig)

		let nonRecoverable = try K1.ECDSA.Signature(rawRepresentation: compactRecoverableSig.compact)

		try XCTAssertEqual(nonRecoverable, recoverableSig.convertToNormal())
		let nonRecovDer = nonRecoverable.derRepresentation
		let nonRecoveryDERHex = "3044022074b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac0220566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8"
		XCTAssertEqual(nonRecovDer.hex, nonRecoveryDERHex)

		try XCTAssertEqual(K1.ECDSA.Signature(derRepresentation: Data(hex: nonRecoveryDERHex)), nonRecoverable)
	}
}

private extension ECDSASignaturePublicKeyRecoveryTests {
	func doTestGroup(
		group: RecoveryTestGroup,
		file: StaticString = #file,
		line: UInt = #line
	) throws -> ResultOfTestGroup {
		var numberOfTestsRun = 0
		for vector in group.tests {
			let publicKeyUncompressed = try [UInt8](hex: vector.publicKeyUncompressed)
			let expectedPublicKey = try K1.ECDSA.KeyRecovery.PublicKey(x963Representation: publicKeyUncompressed)

			XCTAssertEqual(
				try Data(hex: vector.publicKeyCompressed),
				expectedPublicKey.compressedRepresentation
			)

			let recoverableSig = try vector.recoverableSignature()
			try XCTAssertEqual(recoverableSig.compact().recoveryID, vector.recoveryID)

			let hashedMessage = try Data(hex: vector.hashMessage)
			XCTAssertTrue(expectedPublicKey.isValidSignature(recoverableSig, hashed: hashedMessage))
			try XCTAssertEqual(vector.recoveryID, recoverableSig.compact().recoveryID)

			let recoveredPublicKey = try recoverableSig.recoverPublicKey(
				message: hashedMessage
			)

			XCTAssertEqual(expectedPublicKey, recoveredPublicKey)

			XCTAssertTrue(recoveredPublicKey.isValidSignature(recoverableSig, hashed: hashedMessage))

			numberOfTestsRun += 1
		}
		return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
	}
}

// MARK: - RecoveryTestGroup
private struct RecoveryTestGroup: Decodable {
	let tests: [RecoveryTestVector]
}

// MARK: - IncorrectByteCount
struct IncorrectByteCount: Swift.Error {}

// MARK: - RecoveryTestVector
struct RecoveryTestVector: Decodable, Equatable {
	let recoveryID: K1.ECDSA.KeyRecovery.Signature.RecoveryID
	let message: String
	let hashMessage: String
	private let signature: String

	func recoverableSignature() throws -> K1.ECDSA.KeyRecovery.Signature {
		try K1.ECDSA.KeyRecovery.Signature(
			internalRepresentation: Data(hex: signature)
		)
	}

	let publicKeyUncompressed: String
	let publicKeyCompressed: String
}

// MARK: - K1.ECDSA.KeyRecovery.Signature.RecoveryID + ExpressibleByIntegerLiteral
extension K1.ECDSA.KeyRecovery.Signature.RecoveryID: ExpressibleByIntegerLiteral {
	public init(integerLiteral value: UInt8) {
		self.init(rawValue: value)!
	}
}
