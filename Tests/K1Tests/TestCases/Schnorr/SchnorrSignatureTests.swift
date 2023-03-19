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
@testable import FFI

final class SchnorrSignatureTests: XCTestCase {
    
    func testSchnorr() throws {
        let alice = K1.PrivateKey()
        let message = "Send Bob 3 BTC".data(using: .utf8)!
        let signature = try alice.schnorrSign(unhashed: message)
        let isSignatureValid = alice.publicKey.isValidSchnorrSignature(signature, unhashed: message)
        XCTAssertTrue(isSignatureValid, "Signature should be valid.")
    }
    
}

extension K1.PublicKey {
    public func isValidSchnorrSignature<M: DataProtocol>(
        _ signature: SchnorrSignature,
        unhashed: M
    ) -> Bool {
        isValidSchnorrSignature(signature, digest: SHA256.hash(data: unhashed))
    }
}

extension K1.PrivateKey {
    func schnorrSign(
        unhashed: some DataProtocol,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try schnorrSign(digest: SHA256.hash(data: unhashed), input: maybeInput)
    }
}
