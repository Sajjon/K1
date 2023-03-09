// From: https://github.com/apple/swift-crypto/blob/main/Tests/CryptoTests/ECDH/secpECDH_Runner.swift
// Commit: 794901c991bf3fa0431ba3c0927ba078799c6911

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
@testable import K1

final class ECDHWychoproofTests: XCTestCase {
    
    func testWycheproof() throws {
        let result =  try testSuite(
            jsonName: "ecdh_secp256k1_test",
            testFunction: { (group: ECDHTestGroup) in
                testGroup(group: group)
            })
        
        print("☑️ \(String(describing: result))")
    }
}

private extension ECDHWychoproofTests {
    func testGroup(
        group: ECDHTestGroup,
        skipIfContainsAnyFlag flagsForUnsupportedTestVectors: [String] = ["InvalidAsn", "CompressedPoint", "InvalidPublic", "UnnamedCurve"],
        file: StaticString = #file, line: UInt = #line
    ) -> ResultOfTestGroup {
        func padKeyIfNecessary(vector: String, file: StaticString = #file, line: UInt = #line) throws -> [UInt8] {
            // There are a few edge cases here.
            //
            // First, our raw bytes function requires the
            // input buffer to be exactly as long as the curve size.
            //
            // Second, Wycheproof inputs may be too short or too long with
            // leading zeros.
            let curveSize = K1.Curve.Field.byteCount
            var privateBytes = [UInt8](repeating: 0, count: curveSize)

            let hexFromVector = (vector.count % 2 == 0) ? vector : "0\(vector)"
            let privateKeyVector = try! Array(hex: hexFromVector)

            // Input is too long (i.e. we have leading zeros)
            if privateKeyVector.count > curveSize {
                privateBytes = privateKeyVector.suffix(curveSize)
            } else if privateKeyVector.count == curveSize {
                privateBytes = privateKeyVector
            } else {
                // Input is too short
                privateBytes.replaceSubrange((privateBytes.count - privateKeyVector.count) ..< privateBytes.count, with: privateKeyVector)
            }

            return privateBytes
        }

        var idsOfOmittedTests = Array<Int>()
        var numberOfTestsRun = 0
        
        for testVector in group.tests {
            if !Set(testVector.flags).isDisjoint(with: Set(flagsForUnsupportedTestVectors)) {
                idsOfOmittedTests.append(testVector.tcId)
                continue
            }
            numberOfTestsRun += 1
            do {
                let publicKey = try PublicKey.import(der: Data(hex: testVector.publicKey))
                var privateBytes = [UInt8]()
                privateBytes = try padKeyIfNecessary(vector: testVector.privateKey)
                let privateKey = try PrivateKey.import(rawRepresentation: privateBytes)
                let expectedXComponent = try Data(hex: testVector.shared)
                let sharedPublicKeyPoint = try privateKey.sharedSecret(with: publicKey)
                let sharedPublicKeyXComponent = Data(sharedPublicKeyPoint[1..<33]) // slice out just X component
                XCTAssertEqual(sharedPublicKeyXComponent, expectedXComponent, file: file, line: line)
            } catch {
                if testVector.result != "invalid" {
                    XCTFail("Failed with error: \(String(describing: error)), test vector: \(String(describing: testVector))")
                }
            }
        }
        
        return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests:idsOfOmittedTests)
    }
}

struct ECDHTestGroup: Codable {
    let curve: String
    let tests: [ECDHTestVector]
}

struct ECDHTestVector: Codable {
    let comment: String
    let publicKey: String
    let privateKey: String
    let shared: String
    let result: String
    let tcId: Int
    let flags: [String]

    enum CodingKeys: String, CodingKey {
        case publicKey = "public"
        case privateKey = "private"
        case comment
        case shared
        case result
        case tcId
        case flags
    }
}
