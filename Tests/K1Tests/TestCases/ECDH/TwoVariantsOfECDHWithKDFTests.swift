import Foundation
@testable import K1
@testable import FFI
import CryptoKit
import XCTest

private struct ECDHX963Suite: Decodable {
    let origin: String
    let author: String
    let description: String
    let numberOfTests: Int
    let algorithm: String
    let generatedOn: String // data
    let vectors: [Vector]
}

private struct Vector: Decodable {
    let alicePrivateKey: String
    let bobPrivateKey: String
    let alicePublicKeyUncompressed: String
    let bobPublicKeyUncompressed: String
    let outcomes: [Outcome]
    
    struct Outcome: Decodable {
        enum ECDHVariant: String, Decodable {
            case asn1X963 = "ASN1X963"
            case libsecp256k1 = "Bitcoin"
        }
        let ecdhVariant: ECDHVariant
        let ecdhSharedKey: String
        let derivedKeys: [DerivedKeys]
        struct DerivedKeys: Decodable {
            
            /// Used by both `x963` and `HKDF`
            let info: String
            
            /// `x963` KDF  output
            let x963: String
            
            /// Salt for `HDKF`
            let salt: String
            
            let hkdf: String
        }
    }
}



final class TwoVariantsOfECDHWithKDFTests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }
    func testTwoVariantsOfECDHWithKDF_vectors() throws {
        let fileURL = Bundle.module.url(forResource: "ecdh_secp256k1_two_variants_with_kdf_test", withExtension: ".json")
        let data = try Data(contentsOf: fileURL!)
        let suite = try JSONDecoder().decode(ECDHX963Suite.self, from: data)
        try suite.vectors.forEach(doTest)
    }
}

extension TwoVariantsOfECDHWithKDFTests {
    

    fileprivate func doTest(_ vector: Vector) throws {
        print(String(describing: vector))
        let outputByteCount = 32
        let hash = SHA256.self
        
        let alice = try PrivateKey(hex: vector.alicePrivateKey)
        let bob = try PrivateKey(hex: vector.bobPrivateKey)
        try XCTAssertEqual(alice.publicKey.rawRepresentation(format: .uncompressed).hex, vector.alicePublicKeyUncompressed)
        try XCTAssertEqual(bob.publicKey.rawRepresentation(format: .uncompressed).hex, vector.bobPublicKeyUncompressed)
        
        for outcome in vector.outcomes {
            switch outcome.ecdhVariant {
            case .asn1X963:
                let sharedSecretAB = try alice.sharedSecretFromKeyAgreement(with: bob.publicKey)
                let sharedSecretBA = try bob.sharedSecretFromKeyAgreement(with: alice.publicKey)
                
                XCTAssertEqual(sharedSecretAB, sharedSecretBA)
                sharedSecretAB.withUnsafeBytes {
                    XCTAssertEqual(Data($0).hex, outcome.ecdhSharedKey, "Wrong ECDH secret, mismatched expected from vector.")
                }
                
                for derivedKeys in outcome.derivedKeys {
                    let info = try XCTUnwrap(derivedKeys.info.data(using: .utf8))
                    let salt = try Data(hex: derivedKeys.salt)
                    let x963 = sharedSecretBA.x963DerivedSymmetricKey(using: hash, sharedInfo: info, outputByteCount: outputByteCount)
                    x963.withUnsafeBytes {
                        XCTAssertEqual(Data($0).hex, derivedKeys.x963, "Wrong X963 KDF result, mismatched expected from vector.")
                    }
                    let hkdf = sharedSecretBA.hkdfDerivedSymmetricKey(using: hash, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
                    hkdf.withUnsafeBytes {
                        XCTAssertEqual(Data($0).hex, derivedKeys.hkdf, "Wrong HKDF result, mismatched expected from vector.")
                    }
                }
                
            case .libsecp256k1:
                let sharedSecretAB = try alice.ecdh(with: bob.publicKey)
                let sharedSecretBA = try bob.ecdh(with: alice.publicKey)
                
                XCTAssertEqual(sharedSecretAB, sharedSecretBA)
                sharedSecretAB.withUnsafeBytes {
                    XCTAssertEqual(Data($0).hex, outcome.ecdhSharedKey, "Wrong ECDH secret, mismatched expected from vector.")
                }
                
                for derivedKeys in outcome.derivedKeys {
                    let info = try XCTUnwrap(derivedKeys.info.data(using: .utf8))
                    let salt = try Data(hex: derivedKeys.salt)
                    let x963 = sharedSecretAB.x963DerivedSymmetricKey(using: hash, sharedInfo: info, outputByteCount: outputByteCount)
                    x963.withUnsafeBytes {
                        XCTAssertEqual(Data($0).hex, derivedKeys.x963, "Wrong X963 KDF result, mismatched expected from vector.")
                    }
                    let hkdf = sharedSecretAB.hkdfDerivedSymmetricKey(using: hash, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
                    hkdf.withUnsafeBytes {
                        XCTAssertEqual(Data($0).hex, derivedKeys.hkdf, "Wrong HKDF result, mismatched expected from vector.")
                    }
                }
            }
        
        }
        
    }
    
    
    
}
