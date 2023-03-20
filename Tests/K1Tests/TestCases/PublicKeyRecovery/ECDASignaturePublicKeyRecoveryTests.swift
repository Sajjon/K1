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
    
    func test_conversionRoundtrips() throws {
        let recoverySignatureHex = "acf9e195e094f2f40eb619b9878817ff951b9b11fac37cf0d7290098bbefb574f8606281a2231a3fc781045f2ea4df086936263bbfa8d15ca17fe70e0c3d6e5601"
        let recoverableSigRaw = try Data(hex: recoverySignatureHex)
        let recoverableSig = try ECDSASignatureRecoverable(rawRepresentation: recoverableSigRaw)
        
        let compactRecoverableSig = try recoverableSig.compact()
        
        let compactRecoverableSigRSHex = "74b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8"
        let recid = try ECDSASignatureRecoverable.RecoveryID(recid: 1)
        XCTAssertEqual(compactRecoverableSig.rs.hex, compactRecoverableSigRSHex)
        XCTAssertEqual(compactRecoverableSig.recoveryID, recid)
        
        
        let nonRecoverable = try ECDSASignatureNonRecoverable(compactRepresentation: compactRecoverableSig.rs)
        
        try XCTAssertEqual(nonRecoverable, recoverableSig.nonRecoverable())
        let nonRecovDer = try nonRecoverable.derRepresentation()
        let nonRecoveryDERHex = "3044022074b5efbb980029d7f07cc3fa119b1b95ff178887b919b60ef4f294e095e1f9ac0220566e3d0c0ee77fa15cd1a8bf3b26366908dfa42e5f0481c73f1a23a2816260f8"
        XCTAssertEqual(nonRecovDer.hex, nonRecoveryDERHex)
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
            let expectedPublicKey =  try K1.PublicKey.init(x963Representation: publicKeyUncompressed)
         
            XCTAssertEqual(
                try Data(hex: vector.publicKeyCompressed),
                try expectedPublicKey.rawRepresentation(format: .compressed)
            )
         

            let recoverableSig = try vector.recoverableSignature()
            try XCTAssertEqual(recoverableSig.compact().recoveryID, vector.recoveryID)
            
            let hashedMessage = try Data(hex: vector.hashMessage)
            XCTAssertTrue(expectedPublicKey.isValidECDSASignature(recoverableSig, hashed: hashedMessage))
            try XCTAssertTrue(expectedPublicKey.isValidECDSASignature(recoverableSig.nonRecoverable(), hashed: hashedMessage))
            try XCTAssertEqual(vector.recoveryID, recoverableSig.compact().recoveryID)
            
            let recoveredPublicKey = try recoverableSig.recoverPublicKey(
                message: hashedMessage
            )
            
            XCTAssertEqual(expectedPublicKey, recoveredPublicKey)
            
            XCTAssertTrue(recoveredPublicKey.isValidECDSASignature(recoverableSig, hashed: hashedMessage))
            try XCTAssertTrue(recoveredPublicKey.isValidECDSASignature(recoverableSig.nonRecoverable(), hashed: hashedMessage))
                   
            let recoveredWithID = try recoverableSig.nonRecoverable().recoverPublicKey(
                recoveryID: vector.recoveryID,
                message: hashedMessage
            )
            XCTAssertEqual(expectedPublicKey, recoveredWithID)
            
            
            numberOfTestsRun += 1
        }
        return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
    }
}

private struct RecoveryTestGroup: Decodable {
    let tests: [RecoveryTestVector]
}

struct IncorrectByteCount: Swift.Error {}
struct RecoveryTestVector: Decodable, Equatable {
    let recoveryID: ECDSASignatureRecoverable.RecoveryID
    let message: String
    let hashMessage: String
    private let signature: String

    
    func recoverableSignature() throws -> ECDSASignatureRecoverable {
        try ECDSASignatureRecoverable(
            rawRepresentation: Data(hex: signature)
        )
    }
    
    let publicKeyUncompressed: String
    let publicKeyCompressed: String
}

extension ECDSASignatureRecoverable.RecoveryID: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt8) {
        self.init(rawValue: value)!
    }
}

