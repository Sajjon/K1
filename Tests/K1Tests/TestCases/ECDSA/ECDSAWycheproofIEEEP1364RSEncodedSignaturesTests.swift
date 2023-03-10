import Foundation
import XCTest
import CryptoKit
@testable import K1

final class ECDSA_Wycheproof_IEEE_P1364_RS_EncodedSignaturesTests: XCTestCase {
    
    func testWycheProofSecp256k1_P1364_RS() throws {
        let result: TestResult =
        try testSuite(
            /* https://github.com/google/wycheproof/blob/master/testvectors/ecdsa_secp256k1_sha256_test.json */
            jsonName: "ecdsa_secp256k1_sha256_p1363_RS_test",
            testFunction: { (group: ECDSAWycheTestGroup<SignatureWycheproofP1364TestVector>) in
                try doTestGroup(
                    group: group,
                    signatureValidationMode: .acceptSignatureMalleability,
                    hashFunction: SHA256.self,
                    skipIfContainsFlags: .init(["MissingZero", "BER"]),
                    skipIfContainsComment: ["r too large"]
                )
            })
        
        print("☑️ Test result: \(String(describing: result))")
    }
}
 


private struct SignatureWycheproofP1364TestVector: WycheproofTestVector {
    
    typealias MessageDigest = SHA256.Digest
    typealias Signature = ECDSASignatureNonRecoverable
    
    let comment: String
    let msg: String
    let sig: String
    let result: String
    let flags: [String]
    let tcId: Int
    
    func messageDigest() throws -> MessageDigest {
        let msg = try Data(hex: msg)
        return SHA256.hash(data: msg)
    }
    func expectedSignature() throws -> Signature {
        let raw = try Data(hex: sig)
        guard raw.count >= 64 else {
            struct TooFewBytes: Swift.Error {}
            throw TooFewBytes()
        }
        let signature = try Signature(p1364: raw)
        if self.result == "valid" {
            try XCTAssertEqual(sig, signature.p1364().hex)
        }
        return signature
    }
    
}


