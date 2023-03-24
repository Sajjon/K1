import Foundation
import K1
import XCTest

final class PerformanceTests: XCTestCase {
    
    func testPerformance() {
        let message = [UInt8](repeating: 0xab, count: 32)
        measure {
            do {
                for _ in 0 ..< 10 {
                    let schnorrPrivateKey = K1.Schnorr.PrivateKey()
                    let schnorrPublicKey = schnorrPrivateKey.publicKey
                    
                    try XCTAssertEqual(
                        K1.Schnorr.PublicKey(compressedRepresentation: schnorrPublicKey.compressedRepresentation),
                        schnorrPublicKey
                    )
                    try XCTAssertEqual(
                        K1.Schnorr.PublicKey(x963Representation: schnorrPublicKey.x963Representation),
                        schnorrPublicKey
                    )
                    
                    let ecdsaPrivateKey = K1.PrivateKey()
                    let ecdsaPublicKey = ecdsaPrivateKey.publicKey
                    
                    try XCTAssertEqual(
                        K1.PublicKey(compressedRepresentation: ecdsaPublicKey.compressedRepresentation),
                        ecdsaPublicKey
                    )
                    try XCTAssertEqual(
                        K1.PublicKey(x963Representation: ecdsaPublicKey.x963Representation),
                        ecdsaPublicKey
                    )
                    
                    let ecdsa = try ecdsaPrivateKey.ecdsaSignRecoverable(hashed: message)
                    XCTAssertTrue(
                        ecdsaPublicKey.isValidECDSASignature(
                            ecdsa,
                            hashed: message
                        )
                    )
                    try XCTAssertEqual(
                        K1.ECDSA.Recoverable.Signature(compact: ecdsa.compact()),
                        ecdsa
                    )
                    try XCTAssertEqual(
                        K1.ECDSA.NonRecoverable.Signature(compactRepresentation: ecdsa.nonRecoverable().compactRepresentation()),
                        ecdsa.nonRecoverable()
                    )
                    try XCTAssertEqual(
                        K1.ECDSA.NonRecoverable.Signature(derRepresentation: ecdsa.nonRecoverable().derRepresentation()),
                        ecdsa.nonRecoverable()
                    )
                    
                    let schnorr = try schnorrPrivateKey.sign(hashed: message)
                    XCTAssertTrue(
                        schnorrPublicKey.isValidSignature(
                            schnorr,
                            hashed: message
                        )
                    )
                    try XCTAssertEqual(
                        K1.Schnorr.Signature(rawRepresentation: schnorr.rawRepresentation),
                        schnorr
                    )
                    
                    let alicePrivateKey = try K1.KeyAgreement.PrivateKey(x963Representation: ecdsaPrivateKey.x963Representation)
                    let alicePublicKey = alicePrivateKey.publicKey
                    let bobPrivateKey = K1.KeyAgreement.PrivateKey()
                    let bobPublicKey = bobPrivateKey.publicKey

                    var ab = try alicePrivateKey.sharedSecretFromKeyAgreement(with: bobPublicKey)
                    var ba = try bobPrivateKey.sharedSecretFromKeyAgreement(with: alicePublicKey)
                    XCTAssertEqual(ab, ba)
                    ab = try alicePrivateKey.ecdh(with: bobPublicKey)
                    ba = try bobPrivateKey.ecdh(with: alicePublicKey)
                    XCTAssertEqual(ab, ba)
                }
            } catch {
                XCTFail("abort")
            }
        }
        
    }

}

