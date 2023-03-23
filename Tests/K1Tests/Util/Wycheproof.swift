// From: https://github.com/apple/swift-crypto/blob/main/Tests/_CryptoExtrasTests/Utils/Wycheproof.swift
// Commit: 794901c991bf3fa0431ba3c0927ba078799c6911

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest
import CryptoKit

@testable import K1

struct TestSuite<T: Decodable>: Decodable {
    let algorithm: String
    let numberOfTests: UInt32
    let testGroups: [T]
}

struct TestResult {
    let numberOfTestsInSource: Int
    
    /// Might be less than `numberOfTestsInSource` if some tests were omitted.
    let numberOfTestsRun: Int
    
    let idsOfOmittedTests: [Int]
}

extension XCTestCase {
    func testSuite<T: Decodable>(
        jsonName: String,
        file: StaticString = #file,
        line: UInt = #line,
        testFunction: (T) throws -> ResultOfTestGroup
    ) throws -> TestResult {
        let fileURL = Bundle.module.url(forResource: jsonName, withExtension: ".json")
        let data = try Data(contentsOf: fileURL!)

        let decoder = JSONDecoder()
        let wpTest = try decoder.decode(TestSuite<T>.self, from: data)
        var numberOfTestsRun = 0
        var idsOfOmittedTests = Array<Int>()
        for group in wpTest.testGroups {
            let resultOfGroup = try testFunction(group)
            numberOfTestsRun += resultOfGroup.numberOfTestsRun
            idsOfOmittedTests.append(contentsOf: resultOfGroup.idsOmittedTests)
        }
        return .init(
            numberOfTestsInSource: Int(wpTest.numberOfTests),
            numberOfTestsRun: numberOfTestsRun,
            idsOfOmittedTests: idsOfOmittedTests
        )
    }
    
}
struct ResultOfTestGroup {
    let numberOfTestsRun: Int
    let idsOmittedTests: [Int]
}

extension XCTestCase {
    
    func doTestGroup<HF: HashFunction, TV: WycheproofTestVector>(
        group: ECDSAWycheTestGroup<TV>,
        signatureValidationMode: K1.ECDSA.ValidationInput = .default,
        hashFunction: HF.Type,
        skipIfContainsFlags: [String] = [],
        skipIfContainsComment: [String] = [],
        file: StaticString = #file,
        line: UInt = #line
    ) throws -> ResultOfTestGroup {
        guard group.key.curve == "secp256k1" else {
            let errorMessage = "Key in test group is on wrong EC curve: \(group.key.curve), expected 'secp256k1'"
            throw ECDSASignatureTestError(description: errorMessage)
        }
        let keyBytes = try Array(hex: group.key.uncompressed)
        let key = try PublicKey(x963Representation: keyBytes)
        
        let keyFromDER = try PublicKey(derRepresentation: Data(hex: group.keyDer))
        XCTAssertEqual(key.derRepresentation.hex, group.keyDer)
        XCTAssertEqual(keyFromDER, key)
        
        let keyFromPEM = try PublicKey(pemRepresentation: group.keyPem)
        XCTAssertEqual(key.pemRepresentation, group.keyPem)
        XCTAssertEqual(keyFromPEM, key)

        
        let compactXRaw = try Data(hex: group.key.wx)
        let compactYRaw = try Data(hex: group.key.wy)
        func ensure32Bytes(_ compactComponent: Data) throws -> Data {
            if compactComponent.count == Curve.Field.byteCount {
                return compactComponent
            }
            
            var compactComponent = [UInt8](compactComponent)
            while compactComponent.count < Curve.Field.byteCount {
                compactComponent = [0x00] + compactComponent
            }
            while compactComponent.count > Curve.Field.byteCount {
                guard compactComponent.first == 0x00 else {
                    throw BadKeyComponent()
                }
                compactComponent = [UInt8](compactComponent.dropFirst())
            }
            return Data(compactComponent)
        }
        let xOnly = try ensure32Bytes(compactXRaw)
        let yOnly = try ensure32Bytes(compactYRaw)
            
        let fromRaw = try PublicKey(rawRepresentation: xOnly + yOnly)
        XCTAssertEqual(fromRaw, key)
        
        let fromCompact = try PublicKey(compactRepresentation: xOnly)
        XCTAssertEqual(fromCompact.compressedRepresentation.hex, key.compressedRepresentation.hex)
        
        var numberOfTestsRun = 0
        var idsOfOmittedTests = Array<Int>()
    outerloop: for testVector in group.tests {
        let testVectorFlags = Set(testVector.flags)
        if testVector.msg == "" || !testVectorFlags.isDisjoint(with: Set(skipIfContainsFlags)) {
            idsOfOmittedTests.append(testVector.tcId)
            continue
        }
        
        for comment in skipIfContainsComment {
            if testVector.comment.contains(comment) {
                idsOfOmittedTests.append(testVector.tcId)
                continue outerloop
            }
        }
  
        numberOfTestsRun += 1
        var isValid = false
        do {
            let signature = try testVector.expectedSignature()
            let messageDigest = try testVector.messageDigest()
            
            isValid = key.isValidECDSASignature(
                signature,
                digest: messageDigest,
                input: signatureValidationMode
            )
        } catch {
            let expectedFailure = testVector.result == "invalid" || testVector.result == "acceptable"
            let errorMessage = String(describing: error)
            if !expectedFailure {
                print("❌ Test ID: \(testVector.tcId) is valid, but failed \(errorMessage).")
            }
            XCTAssert(expectedFailure, "Test ID: \(testVector.tcId) is valid, but failed \(errorMessage).", file: file, line: line)
            continue
        }
        
        switch testVector.result {
        case "valid":
            if !isValid {
                print("❌ Test vector is valid, but is rejected \(testVector.tcId)")
            }
            XCTAssert(isValid, "Test vector is valid, but is rejected \(testVector.tcId)", file: file, line: line)
        case "acceptable":
            XCTAssert(isValid, "'acceptable' test vector, expected isValid to be `true`, but was not, tcID: \(testVector.tcId)" ,file: file, line: line)
        case "invalid":
            if isValid {
                print("❌ Test ID: \(testVector.tcId) is valid (we expected 'invalid'), but failed.")
            }
            XCTAssert(!isValid, "Test ID: \(testVector.tcId) is valid (we expected 'invalid'), but failed.", file: file, line: line)
        default:
            XCTFail("Unhandled test vector", file: file, line: line)
        }
    }
        return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: idsOfOmittedTests)
    }
}



struct ECDSATestGroup<TV: SignatureTestVector>: Codable {
    let tests: [TV]
}


struct ECDSAWycheTestGroup<TV: WycheproofTestVector>: Codable {
    let tests: [TV]
    let key: ECDSAKey
    let keyDer: String
    let keyPem: String
}


struct ECDSAKey: Codable {
    let uncompressed: String
    let wx: String
    let wy: String
    let curve: String
}


protocol SignatureTestVector: Codable {
    associatedtype MessageDigest: Digest
    associatedtype Signature: ECSignature
    func messageDigest() throws -> MessageDigest
    func expectedSignature() throws -> Signature
}
protocol WycheproofTestVector: SignatureTestVector where Signature == ECDSASignatureNonRecoverable {
    var flags: [String] { get }
    var tcId: Int { get }
    var result: String { get }
    var msg: String { get }
    var comment: String { get }
}


typealias PublicKey = K1.PublicKey
typealias PrivateKey = K1.PrivateKey


struct ECDSASignatureTestError: Swift.Error, CustomStringConvertible {
    let description: String
}
struct BadKeyComponent: Swift.Error {}
