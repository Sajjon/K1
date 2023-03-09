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
import CryptoKit
@testable import K1

final class ECDSA_Wycheproof_ASN_DER_EncodedSignaturesTests: XCTestCase {
    
    func testWycheProofSecp256k1_DER() throws {
        let result: TestResult = try testSuite(
            /* https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp256k1_sha256_test.json */
            jsonName: "ecdsa_secp256k1_sha256_der_test",
            testFunction: { (group: ECDSAWycheTestGroup<SignatureWycheproofDERTestVector>) in
                
                try doTestGroup(
                    group: group,
                    hashFunction: SHA256.self,
                    skipIfContainsFlags: .init(["MissingZero", "BER"])
                )
                
            })
        print("☑️ Test result: \(String(describing: result))")
    }
}

extension XCTestCase {
    
    func doTestGroup<HF: HashFunction, TV: WycheproofTestVector>(
        group: ECDSAWycheTestGroup<TV>,
        hashFunction: HF.Type,
        skipIfContainsFlags: [String],
        file: StaticString = #file,
        line: UInt = #line
    ) throws -> ResultOfTestGroup {
        guard group.key.curve == "secp256k1" else {
            let errorMessage = "Key in test group is on wrong EC curve: \(group.key.curve), expected 'secp256k1'"
            throw ECDSASignatureTestError(description: errorMessage)
        }
        let keyBytes = try Array(hex: group.key.uncompressed)
        let key = try PublicKey(x963Representation: keyBytes)
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
                let signature = try testVector.expectedSignature()
                let messageDigest = try testVector.messageDigest()
                isValid = try key.isValidECDSASignature(
                    signature,
                    digest: messageDigest,
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

struct ECDSATestGroup<TV: SignatureTestVector>: Codable {
    let tests: [TV]
}


struct ECDSAWycheTestGroup<TV: WycheproofTestVector>: Codable {
    let tests: [TV]
    let key: ECDSAKey
}


struct ECDSAKey: Codable {
    let uncompressed: String
    let curve: String
}

protocol SignatureTestVector: Codable {
    associatedtype MessageDigest: Digest
    associatedtype Signature: ECSignature
    func messageDigest() throws -> MessageDigest
    func expectedSignature() throws -> Signature
}
protocol WycheproofTestVector: SignatureTestVector where Signature == ECDSASignature {
    var flags: [String] { get }
    var tcId: Int { get }
    var result: String { get }
    var msg: String { get }
}

private struct SignatureWycheproofDERTestVector: WycheproofTestVector {
    
    typealias MessageDigest = SHA256.Digest
    typealias Signature = ECDSASignature
    
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
        let derData = try Data(hex: sig)
        return try ECDSASignature.import(fromDER: derData)
    }
    
}

typealias PublicKey = K1.PublicKey
extension PublicKey {
    init(x963Representation: [UInt8]) throws {
        self = try Self.import(from: x963Representation)
    }
}
typealias PrivateKey = K1.PrivateKey


struct ECDSASignatureTestError: Swift.Error, CustomStringConvertible {
    let description: String
}
