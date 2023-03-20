//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-04.
//

import Foundation
@testable import K1
import XCTest

final class PublicKeyImportTests: XCTestCase {
    func testAssertImportingPublicKeyWithTooFewBytesThrowsError() throws {
        let raw = try Data(hex: "deadbeef")
        assert(
            try PublicKey.init(x963Representation: raw),
            throws: K1.Error.incorrectByteCountOfPublicKey(providedByteCount: raw.count)
        )
    }
    
    func testAssertImportingPublicKeyWithTooManyBytesThrowsError() throws {
        let raw = Data(repeating: 0xde, count: 66)
        assert(
            try PublicKey(x963Representation: raw),
            throws: K1.Error.incorrectByteCountOfPublicKey(providedByteCount: raw.count)
        )
    }
    
    func testAssertImportingInvalidUncompressedPublicKeyThrowsError() throws {
        let raw = Data(repeating: 0x04, count: 65)
        assert(
            try PublicKey(x963Representation: raw),
            throws: K1.Error.failedToDeserializePublicKey
        )
    }
    
    func testAssertImportingInvalidCompressedPublicKeyThrowsError() throws {
        let raw = Data(repeating: 0x03, count: 33)
        assert(
            try PublicKey(x963Representation: raw),
            throws: K1.Error.failedToDeserializePublicKey
        )
    }
    
    func testAssertImportValidPublicKeyWorks() throws {
        let raw = Data(repeating: 0x02, count: 33)
        let publicKey = try PublicKey(x963Representation: raw)
        try XCTAssertEqual(publicKey.rawRepresentation(format: .uncompressed).hex, "040202020202020202020202020202020202020202020202020202020202020202415456f0fc01d66476251cab4525d9db70bfec652b2d8130608675674cde64b2")
    }
    
    func test_compress_pubkey() throws {
        let raw = Data(repeating: 0x02, count: 33)
        let publicKey = try PublicKey(x963Representation: raw)
        try XCTAssertEqual(publicKey.rawRepresentation(format: .compressed).hex, "020202020202020202020202020202020202020202020202020202020202020202")
        try XCTAssertEqual(publicKey.rawRepresentation(format: .uncompressed).hex, "040202020202020202020202020202020202020202020202020202020202020202415456f0fc01d66476251cab4525d9db70bfec652b2d8130608675674cde64b2")
    }
    
    func testNotOnCurve() throws {
        /// Public key from `ecdh_secp256k1_test.json` in Wycheproof
        /// Vector id: 185
        /// With "comment" : "point is not on curve"
        /// DER => raw
        let raw = try Data(hex: "040000000000000000000000000000000000000000000000000000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e")
        
        assert(
            try PublicKey(x963Representation: raw),
            throws: K1.Error.failedToDeserializePublicKey
        )
    }
}
