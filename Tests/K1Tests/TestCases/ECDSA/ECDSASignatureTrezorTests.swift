import XCTest
import CryptoKit
@testable import K1

/// Test vectors from [trezor][trezor], signature data from [oleganza][oleganza]
///
/// More vectors can be founds on bitcointalk forum, [here][bitcointalk1] and [here][bitcointalk2] (unreliable?)
///
/// [trezor]: https://github.com/trezor/trezor-crypto/blob/957b8129bded180c8ac3106e61ff79a1a3df8893/tests/test_check.c#L1959-L1965
/// [oleganza]: https://github.com/oleganza/CoreBitcoin/blob/master/CoreBitcoinTestsOSX/BTCKeyTests.swift
/// [bitcointalk1]: https://bitcointalk.org/index.php?topic=285142.msg3300992#msg3300992
/// [bitcointalk2]: https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
final class ECDSASignatureTrezorsTests: XCTestCase {
    
    func testTrezorSecp256k1() throws {
        let result: TestResult = try testSuite(
            jsonName: "ecdsa_secp256k1_sha256_rfc6979_trezor_test",
            testFunction: { group in
                try doTestGroup(
                    group: group
                )
                
            }
        )
        
        print("☑️ Test result: \(String(describing: result))")
    }
    
}
 
private extension XCTestCase {
    
    func doTestGroup(
        group: ECDSATestGroup<SignatureTrezorTestVector>,
        file: StaticString = #file,
        line: UInt = #line
    ) throws -> ResultOfTestGroup {
        var numberOfTestsRun = 0
        for vector in group.tests {
            let privateKey = try K1.PrivateKey.import(rawRepresentation: Data(hex: vector.privateKey))
            let publicKey = privateKey.publicKey
            
            let expectedSignature = try vector.expectedSignature()
            let messageDigest = try vector.messageDigest()
            XCTAssertTrue(try publicKey.isValidECDSASignature(expectedSignature, digest: messageDigest))
            
            let signatureFromMessage = try privateKey.ecdsaSignNonRecoverable(digest: messageDigest)
//            XCTAssertEqual(signatureFromMessage, expectedSignature)
            numberOfTestsRun += 1
        }
        return .init(numberOfTestsRun: numberOfTestsRun, idsOmittedTests: [])
    }
}


private struct SignatureTrezorTestVector: SignatureTestVector {
    
    typealias MessageDigest = SHA256.Digest
    typealias Signature = ECDSASignatureNonRecoverable
    
    let msg: String
    let privateKey: String
    let expected: Expected
    struct Expected: Codable {
        let k: String
        let r: String
        let s: String
        let der: String
    }
    let tcId: Int
    
    func messageDigest() throws -> MessageDigest {
        let messageToHash = msg.data(using: .utf8)!
        return SHA256.hash(data: messageToHash)
    }
    func expectedSignature() throws -> Signature {
        let derData = try Data(hex: expected.der)
        return try ECDSASignatureNonRecoverable.import(fromDER: derData)
    }
    
}

