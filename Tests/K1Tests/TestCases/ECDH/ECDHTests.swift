//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-03.
//

import Foundation
@testable import K1
import XCTest

final class ECDHTests: XCTestCase {
    
    func testECDHX963() throws {
        let alice = try K1.PrivateKey.generateNew()
        let bob = try K1.PrivateKey.generateNew()
        
        let ab = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
        let ba = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)
        ab.withUnsafeBytes {
            XCTAssertEqual(Data($0).count, 32)
        }
        XCTAssertEqual(ab, ba, "Alice and Bob should be able to agree on the same secret")
    }
  
    func testECDHLibsecp256k1() throws {
        let alice = try K1.PrivateKey.generateNew()
        let bob = try K1.PrivateKey.generateNew()
        
        let ab = try alice.ecdh(with: bob.publicKey)
        let ba = try bob.ecdh(with: alice.publicKey)
        XCTAssertEqual(ab, ba, "Alice and Bob should be able to agree on the same secret")
        XCTAssertEqual(ab.count, 32)
    }
    
    func testECDHPoint() throws {
        let alice = try K1.PrivateKey.generateNew()
        let bob = try K1.PrivateKey.generateNew()
        
        let ab = try alice.ecdhPoint(with: bob.publicKey)
        let ba = try bob.ecdhPoint(with: alice.publicKey)
        XCTAssertEqual(ab, ba, "Alice and Bob should be able to agree on the same secret")
        XCTAssertEqual(ab.count, 65)
    }
    
    /// Test vectors from: https://crypto.stackexchange.com/q/57695
    func test_crypto_stackexchange_vector() throws {
        let privateKey1 = try PrivateKey(hex: "82fc9947e878fc7ed01c6c310688603f0a41c8e8704e5b990e8388343b0fd465")
        let privateKey2 = try PrivateKey(hex: "5f706787ac72c1080275c1f398640fb07e9da0b124ae9734b28b8d0f01eda586")
        
        let libsecp256k1 = try privateKey1.ecdh(with: privateKey2.publicKey)
        let ans1X963 = try privateKey1.sharedSecretFromKeyAgreement(with: privateKey2.publicKey).withUnsafeBytes({ Data($0) })
        
        XCTAssertEqual(libsecp256k1.hex, "5935d0476af9df2998efb60383adf2ff23bc928322cfbb738fca88e49d557d7e")
        XCTAssertEqual(ans1X963.hex, "3a17fe5fa33c4f2c7e61799a65061214913f39bfcbee178ab351493d5ee17b2f")
        
    }
    
    /// Assert we do not introduce any regression bugs for the custom ECDh `ecdhPoint`
    func testECDHCustom() throws {
        let alice = try K1.PrivateKey.import(rawRepresentation: Data(repeating: 0xAA, count: 32))
        let bob = try K1.PrivateKey.import(rawRepresentation: Data(repeating: 0xBB, count: 32))
        let ab = try alice.ecdhPoint(with: bob.publicKey)
        let ba = try bob.ecdhPoint(with: alice.publicKey)
        XCTAssertEqual(ab, ba, "Alice and Bob should be able to agree on the same secret")
        XCTAssertEqual(ab.hex, "041d3e7279da3f845c4246087cdd3dd42bea3dea7245ceaf75609d8eb0a4e89c4e8e7a7c012045a2eae87463012468d7aae911b8a1140e240c828c96d9b19bd8e7")
        
    }
}

extension K1.PrivateKey {
    init(hex: String) throws {
        self = try Self.import(rawRepresentation: Data(hex: hex))
    }
}
