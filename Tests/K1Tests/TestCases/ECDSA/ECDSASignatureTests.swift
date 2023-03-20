//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-03.
//

import Foundation
import K1
import XCTest
import CryptoKit

final class ECDSASignatureTests: XCTestCase {
    func testECDSA() throws {
        let alice = K1.PrivateKey()
        let message = "Send Bob 3 BTC".data(using: .utf8)!
        let signature = try alice.ecdsaSignNonRecoverable(unhashed: message)
        let isSignatureValid = alice.publicKey.isValidECDSASignature(signature, unhashed: message)
        XCTAssertTrue(isSignatureValid, "Signature should be valid.")
    }

}

extension K1.PublicKey {
    /// `SHA256` hashed messages and converts a
    /// recoverable ECDSA signature to non-recoverable and
    /// validates it against the hashed message for this public key.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureRecoverable,
        unhashed: some DataProtocol,
        input: K1.ECDSA.ValidationInput = .default
    ) -> Bool {
        do {
            return try isValidECDSASignature(
                signature.nonRecoverable(),
                unhashed: unhashed,
                input: input
            )
        } catch {
            return false
        }
    }
    
    
    /// Verifies an elliptic curve digital signature algorithm (ECDSA) signature on a block of data, by first SHA over the P-256 elliptic curve.
    public func isValidECDSASignature(
        _ signature: ECDSASignatureNonRecoverable,
        unhashed: some DataProtocol,
        input: K1.ECDSA.ValidationInput = .default
    ) -> Bool {
        isValidECDSASignature(
            signature,
            digest: SHA256.hash(data: unhashed),
            input: input
        )
    }
}
