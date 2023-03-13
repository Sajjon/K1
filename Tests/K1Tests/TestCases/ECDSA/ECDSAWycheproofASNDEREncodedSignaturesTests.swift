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
                    signatureValidationMode: .acceptSignatureMalleability,
                    hashFunction: SHA256.self,
                    skipIfContainsFlags: .init(["MissingZero", "BER"])
                )
                
            })
        print("☑️ Test result: \(String(describing: result))")
    }
}

private struct SignatureWycheproofDERTestVector: WycheproofTestVector {
    
    typealias MessageDigest = SHA256.Digest
    typealias Signature = ECDSASignatureNonRecoverable
    
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
        let signature = try ECDSASignatureNonRecoverable.import(fromDER: derData)
        if self.result == "valid" {
            try XCTAssertEqual(sig, signature.derRepresentation().hex)
        }
        return signature
    }
    
}
