//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-04.
//

import Foundation
import K1
import XCTest

final class PrivateKeyGenerationTests: XCTestCase {

    func testGenerationWorks() throws {
        XCTAssertNoThrow(K1.ECDSA.NonRecoverable.PrivateKey())
    }
    
    func testRandom() throws {
        // The probability of two keys being identical is approximately: 1/2^256
        XCTAssertNotEqual(K1.ECDSA.NonRecoverable.PrivateKey(), K1.ECDSA.NonRecoverable.PrivateKey())
    }
    
}
