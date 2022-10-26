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
