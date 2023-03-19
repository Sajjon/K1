//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

import XCTest
import FFI
import Foundation
@testable import K1

struct SchnorrTestGroup<V: SchnorrTestVector>: Codable {
    let tests: [V]
}

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

struct SchnorrTestVerifyVector: SchnorrTestVector {
    let isValid: Bool
    let messageHex: String
    let tcId: Int
    let publicKeyHex: String
    let signatureCompact: String
    let comment: String?
    let flags: [String]?
}

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

final class SchnorrSignatureBitcoinCoreTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }
    
    func testSchnorrSignBitcoinVectors() throws {
        let result: TestResult = try testSuite(
            /* https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv */
            jsonName: "schnorr_secp256k1_sign_sha256_test",
            testFunction: { (group: SchnorrTestGroup<SchnorrTestSignVector>) in
                var numberOfTestsRun = 0
                try group.tests.forEach(doTestSchnorrSign)
                numberOfTestsRun += 1
                return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
            })
        
        print("☑️ Test result: \(String(describing: result))")
    }
    
    func testSchnorrVerifyBitcoinVectors() throws {
        let result: TestResult =
        try testSuite(
            /* https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv */
            jsonName: "schnorr_secp256k1_verify_sha256_test",
            testFunction: { (group: SchnorrTestGroup<SchnorrTestVerifyVector>) in
                var numberOfTestsRun = 0
                try group.tests.forEach(doTestSchnorrVerify)
                numberOfTestsRun += 1
                return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
            })
        
        print("☑️ Test result: \(String(describing: result))")
    }
}

private extension SchnorrSignatureBitcoinCoreTests {
    func doTestSchnorrSign(vector: SchnorrTestSignVector) throws {
        
        let privateKey = try K1.PrivateKey(
            rawRepresentation: Data(hex: vector.privateKeyHex)
        )
        
        let publicKey = privateKey.publicKey
        let expectedPublicKey = try K1.PublicKey(x963Representation: Data(hex: vector.publicKeyHex))
        XCTAssertEqual(publicKey, expectedPublicKey)

        XCTAssertEqual(
            try! publicKey.rawRepresentation(format: .compressed).hex.lowercased(),
            try! expectedPublicKey.rawRepresentation(format: .compressed).hex.lowercased()
            )

        let message = try Data(hex: vector.messageHex)
        let signature = try privateKey.schnorrSign(
            hashed: message,
            input: .init(auxilaryRandomData: Data(hex: vector.auxDataHex))
        )

        let expectedSig = try SchnorrSignature(rawRepresentation: Data(hex: vector.signatureCompact))

        XCTAssertEqual(signature.rawRepresentation.hex, vector.signatureCompact)

        XCTAssertEqual(
            publicKey.isValidSchnorrSignature(expectedSig, hashed: message),
            vector.isValid
        )
    }
    
    func doTestSchnorrVerify(vector: SchnorrTestVector) throws {
        func parsePublicKey() throws -> PublicKey {
            try PublicKey(x963Representation: Data(hex: vector.publicKeyHex))
        }
        guard !vector.invalidPublicKey else {
            XCTAssertThrowsError(try parsePublicKey(), "") { anyError in
                if let error = anyError as? Bridge.Error {
                    XCTAssertEqual(error, Bridge.Error.failedToDeserializePublicKey)
                } else {
                    XCTFail("Failed to cast error")
                }
            }
            return
        }
        let publicKey = try parsePublicKey()
        
        let signature =  try SchnorrSignature(rawRepresentation: Data(hex: vector.signatureCompact))
        
        let validSignature = try publicKey.isValidSchnorrSignature(
            signature, hashed: Data(hex: vector.messageHex)
        )
        
        XCTAssertEqual(validSignature, vector.isValid)
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
