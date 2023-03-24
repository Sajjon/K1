//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-21.
//
import Foundation
@testable import K1
import XCTest


final class PrivateKeyEncodingTests: XCTestCase {
    
    func testRawRoundtrip() throws {
        try doTest(
            serialize: \.rawRepresentation,
            deserialize: K1.ECDSA.NonRecoverable.PrivateKey.init(rawRepresentation:)
        )
    }
    
    func testx963Roundtrip() throws {
        try doTest(
            serialize: \.x963Representation,
            deserialize: K1.ECDSA.NonRecoverable.PrivateKey.init(x963Representation:)
        )
    }
    
    func testDERRoundtrip() throws {
        try doTest(
            serialize: \.derRepresentation,
            deserialize: K1.ECDSA.NonRecoverable.PrivateKey.init(derRepresentation:)
        )
    }
    
    func testPEMRoundtrip() throws {
        try doTest(
            serialize: \.pemRepresentation,
            deserialize: K1.ECDSA.NonRecoverable.PrivateKey.init(pemRepresentation:)
        )
    }
}

private extension PrivateKeyEncodingTests {
    func doTest<Enc: Equatable>(
        serialize: KeyPath<K1.ECDSA.NonRecoverable.PrivateKey, Enc>,
        deserialize: (Enc) throws -> K1.ECDSA.NonRecoverable.PrivateKey
    ) throws {
        try doTestSerializationRoundtrip(
            original: K1.ECDSA.NonRecoverable.PrivateKey(),
            serialize: serialize,
            deserialize: deserialize
        )
    }
}
