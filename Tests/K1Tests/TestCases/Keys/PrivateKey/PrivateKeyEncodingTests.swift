//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-21.
//
import Foundation
import K1
import XCTest

final class PrivateKeyEncodingTests: XCTestCase {
    
    func testEncodingsPrivateKeyTests() {
        let keyKA = K1.PrivateKey()
        let raw = keyKA.rawRepresentation
        let keyKA_x963 = keyKA.x963Representation
       
        try XCTAssertEqual(
            K1.PrivateKey(rawRepresentation: raw),
            K1.PrivateKey(x963Representation: keyKA_x963)
        )
        
    }

}

