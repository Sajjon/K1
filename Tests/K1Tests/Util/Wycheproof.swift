// swiftformat:disable strip

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

// From: https://github.com/apple/swift-crypto/blob/main/Tests/_CryptoExtrasTests/Utils/Wycheproof.swift
// Commit: 794901c991bf3fa0431ba3c0927ba078799c6911

// swiftformat:enable strip

import CryptoKit
@testable import K1
import XCTest

// MARK: - TestSuite
struct TestSuite<T: Decodable>: Decodable {
	let algorithm: String
	let numberOfTests: UInt32
	let testGroups: [T]
}

// MARK: - TestResult
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
		var idsOfOmittedTests = [Int]()
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

// MARK: - ResultOfTestGroup
struct ResultOfTestGroup {
	let numberOfTestsRun: Int
	let idsOmittedTests: [Int]
}

extension XCTestCase {
	func doTestGroup<HF: HashFunction, TV: WycheproofTestVector>(
		group: ECDSAWycheTestGroup<TV>,
		signatureValidationMode: K1.ECDSA.ValidationOptions = .default,
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
		let key = try K1.ECDSA.PublicKey(x963Representation: keyBytes)

		let keyFromDER = try K1.ECDSA.PublicKey(derRepresentation: Data(hex: group.keyDer))
		XCTAssertEqual(key.derRepresentation.hex, group.keyDer)
		XCTAssertEqual(keyFromDER, key)

		let keyFromPEM = try K1.ECDSA.PublicKey(pemRepresentation: group.keyPem)
		XCTAssertEqual(key.pemRepresentation, group.keyPem)
		XCTAssertEqual(keyFromPEM, key)

		let keyCompactXRaw = try Data(hex: group.key.wx)
		let keyCompactYRaw = try Data(hex: group.key.wy)
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
		let pubKeyXOnly = try ensure32Bytes(keyCompactXRaw)
		let pubKeyYOnly = try ensure32Bytes(keyCompactYRaw)

		let pubKeyFromRaw = try K1.ECDSA.PublicKey(rawRepresentation: pubKeyXOnly + pubKeyYOnly)
		XCTAssertEqual(pubKeyFromRaw, key)

		var numberOfTestsRun = 0
		var idsOfOmittedTests = [Int]()
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

				isValid = key.isValidSignature(
					signature,
					digest: messageDigest,
					options: signatureValidationMode
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
				XCTAssert(isValid, "'acceptable' test vector, expected isValid to be `true`, but was not, tcID: \(testVector.tcId)", file: file, line: line)
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

// MARK: - ECDSATestGroup
struct ECDSATestGroup<TV: SignatureTestVector>: Codable {
	let tests: [TV]
}

// MARK: - ECDSAWycheTestGroup
struct ECDSAWycheTestGroup<TV: WycheproofTestVector>: Codable {
	let tests: [TV]
	let key: ECDSAKey
	let keyDer: String
	let keyPem: String
}

// MARK: - ECDSAKey
struct ECDSAKey: Codable {
	let uncompressed: String
	let wx: String
	let wy: String
	let curve: String
}

// MARK: - SignatureTestVector
protocol SignatureTestVector: Codable {
	associatedtype MessageDigest: Digest
	associatedtype Signature: ECSignature
	func messageDigest() throws -> MessageDigest
	func expectedSignature() throws -> Signature
}

// MARK: - WycheproofTestVector
protocol WycheproofTestVector: SignatureTestVector where Signature == K1.ECDSA.Signature {
	var flags: [String] { get }
	var tcId: Int { get }
	var result: String { get }
	var msg: String { get }
	var comment: String { get }
}

// MARK: - ECDSASignatureTestError
struct ECDSASignatureTestError: Swift.Error, CustomStringConvertible {
	let description: String
}

// MARK: - BadKeyComponent
struct BadKeyComponent: Swift.Error {}
