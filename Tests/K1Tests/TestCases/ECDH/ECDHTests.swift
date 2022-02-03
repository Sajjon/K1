//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-03.
//

import Foundation
import K1
import XCTest

final class ECDHTests: XCTestCase {
    
    func testECDH() throws {
        let alice = try K1.PrivateKey.generateNew()
        let bob = try K1.PrivateKey.generateNew()
        
        let ab = try alice.sharedSecret(with: bob.publicKey)
        let ba = try bob.sharedSecret(with: alice.publicKey)
        XCTAssertEqual(ab, ba, "Alice and Bob should be able to agree on the same secret")
    }
}

