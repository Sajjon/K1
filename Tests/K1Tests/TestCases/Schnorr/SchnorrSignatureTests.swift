//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-03.
//

import Foundation
import K1
import XCTest

final class SchnorrSignatureTests: XCTestCase {
    
    func testSchnorr() throws {
        let alice = try K1.PrivateKey.generateNew()
        let message = "Send Bob 3 BTC".data(using: .utf8)!
        let signature = try alice.schnorrSign(unhashed: message)
        let isSignatureValid = try alice.publicKey.isValidSchnorrSignature(signature, unhashed: message)
        XCTAssertTrue(isSignatureValid, "Signature should be valid.")
    }
    
}
