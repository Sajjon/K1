//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-10-25.
//

import Foundation
@testable import K1
import XCTest

/// Test vectors:
/// https://gist.github.com/webmaster128/130b628d83621a33579751846699ed15
final class ECDASignaturePublicKeyRecoveryTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }
    
    func test_recovery_test_vectors() throws {
        let result: TestResult = try testSuite(
            jsonName: "publickey_recovery",
            testFunction: { (group: RecoveryTestGroup) in
                try doTestGroup(group: group)
            }
        )
        
        print("☑️ Test result: \(String(describing: result))")
    }
}

private extension ECDASignaturePublicKeyRecoveryTests {
    func doTestGroup(
        group: RecoveryTestGroup,
        file: StaticString = #file,
        line: UInt = #line
    ) throws -> ResultOfTestGroup {
        var numberOfTestsRun = 0
        for vector in group.tests {
            let publicKeyUncompressed = try [UInt8](hex: vector.publicKeyUncompressed)
            let expectedPublicKey = try K1.PublicKey(
                wrapped: .init(uncompressedRaw: publicKeyUncompressed)
            )
            XCTAssertEqual(
                try [UInt8](hex: vector.publicKeyCompressed),
                try expectedPublicKey.rawRepresentation(format: .compressed)
            )
            let signatureData = try Data(hex: vector.signature)
            
            XCTAssertThrowsError(try ECDSASignatureNonRecoverable(
                rawRepresentation: signatureData
            ))
            let signature = try ECDSASignatureRecoverable(
                rawRepresentation: signatureData
            )
            let hashedMessage = try Data(hex: vector.hashMessage)
            XCTAssertTrue(try expectedPublicKey.isValid(signature: signature, hashed: hashedMessage))
            XCTAssertTrue(try expectedPublicKey.isValid(signature: signature.nonRecoverable(), hashed: hashedMessage))
            XCTAssertEqual(vector.recoveryID, signature.recoveryID)
            
            let recoveredPublicKey = try signature.recoverPublicKey(
                messageThatWasSigned: hashedMessage
            )
            
            XCTAssertEqual(expectedPublicKey, recoveredPublicKey)
            
            XCTAssertTrue(try recoveredPublicKey.isValid(signature: signature, hashed: hashedMessage))
            XCTAssertTrue(try recoveredPublicKey.isValid(signature: signature.nonRecoverable(), hashed: hashedMessage))
            
            
//            let nonRecoverable = try ECDSASignatureNonRecoverable(rawRepresentation: signatureData.dropLast(1))
//            try XCTAssertEqual(
//                String(vector.signature.prefix(128)),
//                nonRecoverable.p1364().hex
//            )
//            
//            XCTAssertTrue(try expectedPublicKey.isValid(signature: nonRecoverable, hashed: hashedMessage))
//            try XCTAssertEqual(nonRecoverable.p1364().hex, try signature.nonRecoverable().p1364().hex)
//            let recoveredWithID = try nonRecoverable.recoverPublicKey(
//                recoveryID: vector.recoveryID,
//                messageThatWasSigned: hashedMessage
//            )
//            XCTAssertEqual(expectedPublicKey, recoveredWithID)
            
            
            numberOfTestsRun += 1
        }
        return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
    }
}

private struct RecoveryTestGroup: Decodable {
    let tests: [RecoveryTestVector]
}

struct RecoveryTestVector: Decodable, Equatable {
    let recoveryID: Int32
    let message: String
    let hashMessage: String
    let signature: String
    let publicKeyUncompressed: String
    let publicKeyCompressed: String
}
