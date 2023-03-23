import Foundation
import K1
import XCTest

final class PerformanceTests: XCTestCase {
    
    func testPerformance() {
        let message = [UInt8](repeating: 0xab, count: 32)
        measure {
            do {
                for _ in 0 ..< 1000 {
                    let alicePrivateKey = PrivateKey()
                    let alicePublicKey = alicePrivateKey.publicKey
                    
                    try XCTAssertEqual(
                        PublicKey(compressedRepresentation: alicePublicKey.compressedRepresentation),
                        alicePublicKey
                    )
                    try XCTAssertEqual(
                        PublicKey(x963Representation: alicePublicKey.x963Representation),
                        alicePublicKey
                    )
                    
                    let ecdsa = try alicePrivateKey.ecdsaSignRecoverable(hashed: message)
                    XCTAssertTrue(
                        alicePublicKey.isValidECDSASignature(
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
                    
                    let schnorr = try alicePrivateKey.schnorrSign(hashed: message)
                    XCTAssertTrue(
                        alicePublicKey.isValidSchnorrSignature(
                            schnorr,
                            hashed: message
                        )
                    )
                    try XCTAssertEqual(
                        SchnorrSignature(rawRepresentation: schnorr.rawRepresentation),
                        schnorr
                    )
                    
                    let bobPrivateKey = PrivateKey()
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

