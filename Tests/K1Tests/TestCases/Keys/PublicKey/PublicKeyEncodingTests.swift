//
//  File.swift
//
//
//  Created by Alexander Cyon on 2023-03-21.
//

import Foundation
@testable import K1
import XCTest


final class PublicKeyEncodingTests: XCTestCase {
    
    func test_pubkey_raw_is_x963_minus_prefix() throws {
        let privateKey = K1.PrivateKey()
        let publicKey = privateKey.publicKey
        
        XCTAssertEqual(publicKey.rawRepresentation.hex, Data(publicKey.x963Representation.dropFirst()).hex)
    }
    
    func testRawRoundtrip() throws {
        try doTest(
            serialize: \.rawRepresentation,
            deserialize: PublicKey.init(rawRepresentation:)
        )
    }
    
    func testCompressedRoundtrip() throws {
        try doTest(
            serialize: \.compressedRepresentation,
            deserialize: PublicKey.init(compressedRepresentation:)
        )
    }
    
    func testx963Roundtrip() throws {
        try doTest(
            serialize: \.x963Representation,
            deserialize: PublicKey.init(x963Representation:)
        )
    }
    
    func testDERRoundtrip() throws {
        try doTest(
            serialize: \.derRepresentation,
            deserialize: PublicKey.init(derRepresentation:)
        )
    }
    
    func testPEMRoundtrip() throws {
        try doTest(
            serialize: \.pemRepresentation,
            deserialize: PublicKey.init(pemRepresentation:)
        )
    }
}

private extension PublicKeyEncodingTests {
    func doTest<Enc: Equatable>(
        serialize: KeyPath<K1.PublicKey, Enc>,
        deserialize: (Enc) throws -> K1.PublicKey
    ) throws {
        try doTestSerializationRoundtrip(
            original: K1.PublicKey.generateNew(),
            serialize: serialize,
            deserialize: deserialize
        )
    }
}

extension K1.PublicKey {
    static func generateNew() -> Self {
        K1.PrivateKey().publicKey
    }
}

public func doTestSerializationRoundtrip<T, Enc>(
    original makeOriginal: @autoclosure () -> T,
    serialize: KeyPath<T, Enc>,
    deserialize: (Enc) throws -> T
) throws where T: Equatable, Enc: Equatable {
    for _ in 0 ..< 100 {
        let original = makeOriginal()
        let serialized = original[keyPath: serialize]
        let deserialized = try deserialize(serialized)
        XCTAssertEqual(deserialized, original)
        let reserialized = deserialized[keyPath: serialize]
        XCTAssertEqual(reserialized, serialized)
        
    }
}
