// swiftformat:disable strip

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

// From: https://github.com/apple/swift-crypto/blob/main/Tests/CryptoTests/ECDH/secpECDH_Runner.swift
// Commit: 794901c991bf3fa0431ba3c0927ba078799c6911

// swiftformat:enable strip

import Foundation
@testable import K1
import XCTest

// MARK: - ECDHWycheproofTests
final class ECDHWycheproofTests: XCTestCase {
	func testECDHWycheproof() throws {
		let _ = try testSuite(
			jsonName: "wycheproof_ecdh_ASN1x963",
			testFunction: { (group: ECDHTestGroup) in
				testGroup(group: group)
			}
		)
	}
}

private extension ECDHWycheproofTests {
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
			let curveSize = 32 // K1.Curve.Field.byteCount
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

		var idsOfOmittedTests = [Int]()
		var numberOfTestsRun = 0

		for testVector in group.tests {
			if !Set(testVector.flags).isDisjoint(with: Set(flagsForUnsupportedTestVectors)) {
				idsOfOmittedTests.append(testVector.tcId)
				continue
			}
			numberOfTestsRun += 1
			do {
				let publicKey = try K1.KeyAgreement.PublicKey(derRepresentation: Data(hex: testVector.publicKey))
				var privateBytes = [UInt8]()
				privateBytes = try padKeyIfNecessary(vector: testVector.privateKey)
				let privateKey = try K1.KeyAgreement.PrivateKey(rawRepresentation: privateBytes)

				/// ANS1 X9.63 serialization of shared secret, returning a `CryptoKit.SharedSecret`
				let sharedPublicKeyPoint = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
				let got = sharedPublicKeyPoint.withUnsafeBytes {
					Data($0)
				}
				XCTAssertEqual(got.hex, testVector.shared, file: file, line: line)
			} catch {
				if testVector.result != "invalid" {
					XCTFail("Failed with error: \(String(describing: error)), test vector: \(String(describing: testVector))")
				}
			}
		}

		return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: idsOfOmittedTests)
	}
}

// MARK: - ECDHTestGroup
struct ECDHTestGroup: Codable {
	let curve: String
	let tests: [ECDHTestVector]
}

// MARK: - ECDHTestVector
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
