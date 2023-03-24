import Foundation
import K1
import XCTest

final class PerformanceTests: XCTestCase {
    
    func testPerformance() {
        let message = [UInt8](repeating: 0xab, count: 32)
        measure {
            do {
                for _ in 0 ..< 10 {
                    let privateKey = PrivateKey()
                    let publicKey = privateKey.publicKey
                    
                    try XCTAssertEqual(
                        PublicKey(compressedRepresentation: publicKey.compressedRepresentation),
                        publicKey
                    )
                    try XCTAssertEqual(
                        PublicKey(x963Representation: publicKey.x963Representation),
                        publicKey
                    )
                    
                    let ecdsa = try privateKey.ecdsaSignRecoverable(hashed: message)
                    XCTAssertTrue(
                        publicKey.isValidECDSASignature(
                            ecdsa,
                            hashed: message
                        )
                    )
                    try XCTAssertEqual(
                        ECDSASignatureRecoverable(compact: ecdsa.compact()),
                        ecdsa
                    )
                    try XCTAssertEqual(
                        ECDSASignatureNonRecoverable(compactRepresentation: ecdsa.nonRecoverable().compactRepresentation()),
                        ecdsa.nonRecoverable()
                    )
                    try XCTAssertEqual(
                        ECDSASignatureNonRecoverable(derRepresentation: ecdsa.nonRecoverable().derRepresentation()),
                        ecdsa.nonRecoverable()
                    )
                    
                    let schnorr = try privateKey.schnorrSign(hashed: message)
                    XCTAssertTrue(
                        publicKey.isValidSchnorrSignature(
                            schnorr,
                            hashed: message
                        )
                    )
                    try XCTAssertEqual(
                        SchnorrSignature(rawRepresentation: schnorr.rawRepresentation),
                        schnorr
                    )
                    
                    let alicePrivateKey = try K1.KeyAgreement.PrivateKey(x963Representation: privateKey.x963Representation)
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

