// FROM: https://github.com/apple/swift-crypto/blob/main/Tests/CryptoTests/Signatures/ECDSA/ECDSASignatureTests.swift
// commit: 53da7b3706ae6a2bd621becbb201f3d8e24039d6

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import Foundation
import XCTest
import Crypto
@testable import K1

final class ECDSASignatureWycheproofTests: XCTestCase {
    let data = "Testing Signatures".data(using: String.Encoding.utf8)!
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }
    
    func testWycheProofSecp256k1() throws {
        let result: TestResult = try orFail {
            try wycheproofTest(
                /* https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp256k1_sha256_test.json */
                jsonName: "ecdsa_secp256k1_sha256_test",
                testFunction: { (group: ECDSATestGroup) in
                    try orFail {
                        try doTestGroup(
                            group: group,
                            hashFunction: SHA256.self,
                            skipIfContainsFlags: .init(["MissingZero", "BER"])
                        )
                    }
                })
        }
        print("☑️ Test result: \(String(describing: result))")
    }
}

private extension ECDSASignatureWycheproofTests {
    
    func doTestGroup<HF: HashFunction>(
        group: ECDSATestGroup,
        hashFunction: HF.Type,
        skipIfContainsFlags: [String],
        file: StaticString = #file,
        line: UInt = #line
    ) throws -> ResultOfTestGroup {
        guard group.key.curve == "secp256k1" else {
            let errorMessage = "Key in test group is on wrong EC curve: \(group.key.curve), expected 'secp256k1'"
            throw ECDSASignatureTestError(description: errorMessage)
        }
        let keyBytes = try orFail(file: file, line: line) { try Array(hexString: group.key.uncompressed) }
        let key = try orFail(file: file, line: line) { try PublicKey(x963Representation: keyBytes) }
        var numberOfTestsRun = 0
        var idsOfOmittedTests = Array<Int>()
        for testVector in group.tests {
            let testVectorFlags = Set(testVector.flags)
            if testVector.msg == "" || !testVectorFlags.isDisjoint(with: Set(skipIfContainsFlags)) {
                idsOfOmittedTests.append(testVector.tcId)
                continue
            }
            numberOfTestsRun += 1
            var isValid = false
            do {
                let derData = try Data(hexString: testVector.sig)
                let msg = try Data(hexString: testVector.msg)
                let digest = HF.hash(data: msg)
                let signature = try ECDSASignature.import(fromDER: derData)
                isValid = try key.isValidECDSASignature(
                    signature,
                    digest: digest,
                    mode: .acceptSignatureMalleability
                )
            } catch {
                let expectedFailure = testVector.result == "invalid" || testVector.result == "acceptable"
                let errorMessage = String(describing: error)
                XCTAssert(expectedFailure, "Test ID: \(testVector.tcId) is valid, but failed \(errorMessage).", file: file, line: line)
                continue
            }

            switch testVector.result {
            case "valid":
                XCTAssert(isValid, "Test vector is valid, but is rejected \(testVector.tcId)", file: file, line: line)
            case "acceptable":
                XCTAssert(isValid, file: file, line: line)
            case "invalid":
                XCTAssert(!isValid, "Test ID: \(testVector.tcId) is valid, but failed.", file: file, line: line)
            default:
                XCTFail("Unhandled test vector", file: file, line: line)
            }
        }
        return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: idsOfOmittedTests)
    }
}

struct ECDSATestGroup: Codable {
    let tests: [SignatureTestVector]
    let key: ECDSAKey
}

struct ECDSAKey: Codable {
    let uncompressed: String
    let curve: String
}

struct SignatureTestVector: Codable {
    let comment: String
    let msg: String
    let sig: String
    let result: String
    let flags: [String]
    let tcId: Int
}
typealias PublicKey = K1.PublicKey
extension PublicKey {
    init(x963Representation: [UInt8]) throws {
        self = try Self.import(from: x963Representation)
    }
}
typealias PrivateKey = K1.PrivateKey

struct ResultOfTestGroup {
    let numberOfTestsRun: Int
    let idsOmittedTests: [Int]
}

struct ECDSASignatureTestError: Swift.Error, CustomStringConvertible {
    let description: String
}
