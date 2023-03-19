//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-04.
//

import Foundation
@testable import K1
import FFI
import XCTest

final class PrivateKeyImportTests: XCTestCase {

    func testAssertImportingPrivateKeyWithTooFewBytesThrowsError() throws {
        let raw = try Data(hex: "deadbeef")
        assert(
            try PrivateKey(rawRepresentation: raw),
            throws: Bridge.Error.failedToInitializePrivateKeyIncorrectByteCount(got: 4, expected: 32)
        )
    }
    
    func testAssertImportingPrivateKeyWithTooManyBytesThrowsError() throws {
        let raw = Data(repeating: 0xba, count: 33)
        assert(
            try PrivateKey(rawRepresentation: raw),
            throws: Bridge.Error.failedToInitializePrivateKeyIncorrectByteCount(got: 33, expected: 32)
        )
    }
    
    func testAssertImportingPrivateKeyZeroThrowsError() throws {
        let raw = Data(repeating: 0x00, count: 32)
        assert(
            try PrivateKey(rawRepresentation: raw),
            throws: Bridge.Error.invalidPrivateKeyMustNotBeZero
        )
    }
    
    func testAssertImportingPrivateKeyCurveOrderThrowsError() throws {
        let raw = try Data(hex: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
        assert(
            try PrivateKey(rawRepresentation: raw),
            throws: Bridge.Error.invalidPrivateKeyMustBeSmallerThanOrder
        )
    }
    
    func testAssertImportingPrivateKeyLargerThanCurveOrderThrowsError() throws {
        let raw = Data(repeating: 0xff, count: 32)
        assert(
            try PrivateKey(rawRepresentation: raw),
            throws: Bridge.Error.invalidPrivateKeyMustBeSmallerThanOrder
        )
    }
    
    func testAssertPublicKeyOfImportedPrivateKey1() throws {
        let privateKeyRaw = try Data(hex: "0000000000000000000000000000000000000000000000000000000000000001")
        let privateKey = try K1.PrivateKey(rawRepresentation: privateKeyRaw)
        // Easily verified by: https://bitaddress.org/
        // Pretty well known key pair
        let expectedPublicKey = try K1.PublicKey(x963Representation: Data(hex: "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        XCTAssertEqual(privateKey.publicKey, expectedPublicKey)
    }
    
}
