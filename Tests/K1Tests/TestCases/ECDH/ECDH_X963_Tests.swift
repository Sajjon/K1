import Foundation
@testable import K1
import CryptoKit
import XCTest

private struct Vector: Codable {
    let alicePrivateKey: String
    let bobPrivateKey: String
    let alicePublicKeyUncompressed: String
    let bobPublicKeyUncompressed: String
    let ecdhSharedKey: String
    let x963KDFOutput: String
}

private struct ECDHX963Suite: Codable {
    let vectors: [Vector]
}


final class ECDH_X963_Tests: XCTestCase {
    
    func testECDH_X963_vectors() throws {
        let fileURL = Bundle.module.url(forResource: "ecdh_secp256k1_x963_test", withExtension: ".json")
        let data = try Data(contentsOf: fileURL!)
        let suite = try JSONDecoder().decode(ECDHX963Suite.self, from: data)
        try suite.vectors.forEach(doTest)
    }
}

extension ECDH_X963_Tests {
    
    fileprivate func doTest(_ vector: Vector) throws {
        let alice = try PrivateKey(hex: vector.alicePrivateKey)
        let bob = try PrivateKey(hex: vector.bobPrivateKey)
        try XCTAssertEqual(alice.publicKey.rawRepresentation(format: .uncompressed).hex, vector.alicePublicKeyUncompressed)
        try XCTAssertEqual(bob.publicKey.rawRepresentation(format: .uncompressed).hex, vector.bobPublicKeyUncompressed)
        
        let ab = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
        let ba = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)
        XCTAssertEqual(ab, ba, "Alice and Bob should be able to agree on the same secret")
        
        let sharedSecretData = ab.withUnsafeBytes {
            Data($0)
        }
        XCTAssertEqual(sharedSecretData.hex, vector.ecdhSharedKey)
        
        let ab_x963 = ab.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        let ba_x963 = ba.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: Data(), outputByteCount: 32)
        
        XCTAssertEqual(ab_x963, ba_x963, "KDF between secrets should be the same")
        
        let x963Data = ab_x963.withUnsafeBytes {
            Data($0)
        }
        XCTAssertEqual(x963Data.hex, vector.x963KDFOutput)
    }
    
    
    
}
