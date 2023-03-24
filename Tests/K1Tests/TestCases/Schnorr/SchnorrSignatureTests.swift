//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-03.
//

import Foundation
import K1
import XCTest
import CryptoKit

final class SchnorrSignatureTests: XCTestCase {
    
    func testSchnorr() throws {
        let alice = K1.Schnorr.PrivateKey()
        let message = "Send Bob 3 BTC".data(using: .utf8)!
        let signature = try alice.sign(unhashed: message)
        let isSignatureValid = alice.publicKey.isValidSignature(signature, unhashed: message)
        XCTAssertTrue(isSignatureValid, "Signature should be valid.")
    }
    
}
