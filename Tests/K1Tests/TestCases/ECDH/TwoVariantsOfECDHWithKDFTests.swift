import Foundation
@testable import K1
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
    
    func testTwoVariantsOfECDHWithKDF_vectors() throws {
        let fileURL = Bundle.module.url(forResource: "ecdh_secp256k1_two_variants_with_kdf_test", withExtension: ".json")
        let data = try Data(contentsOf: fileURL!)
        let suite = try JSONDecoder().decode(ECDHX963Suite.self, from: data)
        try suite.vectors.forEach(doTest)
    }
}

extension TwoVariantsOfECDHWithKDFTests {
    

    fileprivate func doTest(_ vector: Vector) throws {
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
                    let x963 = x963DerivedSymmetricKey(secret: sharedSecretAB, using: hash, sharedInfo: info, outputByteCount: outputByteCount)
                    x963.withUnsafeBytes {
                        XCTAssertEqual(Data($0).hex, derivedKeys.x963, "Wrong X963 KDF result, mismatched expected from vector.")
                    }
                    let hkdf = hkdfDerivedSymmetricKey(secret: sharedSecretAB, using: hash, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
                    hkdf.withUnsafeBytes {
                        XCTAssertEqual(Data($0).hex, derivedKeys.hkdf, "Wrong HKDF result, mismatched expected from vector.")
                    }
                }
            }
        
        }
        
    }
    
    
    
}

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Copy pasted over from https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Agreement/DH.swift#L48

/// Derives a symmetric encryption key using X9.63 key derivation.
///
/// - Parameters:
///   - hashFunction: The Hash Function to use for key derivation.
///   - sharedInfo: The Shared Info to use for key derivation.
///   - outputByteCount: The length in bytes of resulting symmetric key.
/// - Returns: The derived symmetric key
public func x963DerivedSymmetricKey<H: HashFunction, SI: DataProtocol>(
    secret: Data,
    using hashFunction: H.Type, sharedInfo: SI, outputByteCount: Int
) -> SymmetricKey {
    // SEC1 defines 3 inputs to the KDF:
    //
    // 1. An octet string Z which is the shared secret value. That's `self` here.
    // 2. An integer `keydatalen` which is the length in octets of the keying data to be generated. Here that's `outputByteCount`.
    // 3. An optional octet string `SharedInfo` which consists of other shared data. Here, that's `sharedInfo`.
    //
    // We then need to perform the following steps:
    //
    // 1. Check that keydatalen < hashlen × (2³² − 1). If keydatalen ≥ hashlen × (2³² − 1), fail.
    // 2. Initiate a 4 octet, big-endian octet string Counter as 0x00000001.
    // 3. For i = 1 to ⌈keydatalen/hashlen⌉, do the following:
    //     1. Compute: Ki = Hash(Z || Counter || [SharedInfo]).
    //     2. Increment Counter.
    //     3. Increment i.
    // 4. Set K to be the leftmost keydatalen octets of: K1 || K2 || . . . || K⌈keydatalen/hashlen⌉.
    // 5. Output K.
    //
    // The loop in step 3 is not very Swifty, so instead we generate the counter directly.
    // Step 1: Check that keydatalen < hashlen × (2³² − 1).
    // We do this math in UInt64-space, because we'll overflow 32-bit integers.
    guard UInt64(outputByteCount) < (UInt64(H.Digest.byteCount) * UInt64(UInt32.max)) else {
        fatalError("Invalid parameter size")
    }
    
    var key = SecureBytes()
    key.reserveCapacity(outputByteCount)
    
    var remainingBytes = outputByteCount
    var counter = UInt32(1)
    
    while remainingBytes > 0 {
        // 1. Compute: Ki = Hash(Z || Counter || [SharedInfo]).
        var hasher = H()
        hasher.update(data: secret)
        hasher.update(counter.bigEndian)
        hasher.update(data: sharedInfo)
        let digest = hasher.finalize()
        
        // 2. Increment Counter.
        counter += 1
        
        // Append the bytes of the digest. We don't want to append more than the remaining number of bytes.
        let bytesToAppend = min(remainingBytes, H.Digest.byteCount)
        digest.withUnsafeBytes { digestPtr in
            key.append(digestPtr.prefix(bytesToAppend))
        }
        remainingBytes -= bytesToAppend
    }
    
    precondition(key.count == outputByteCount)
    return SymmetricKey(data: key)
}

extension HashFunction {
    mutating func update(_ counter: UInt32) {
        withUnsafeBytes(of: counter) {
            self.update(bufferPointer: $0)
        }
    }
}


/// From: https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Agreement/DH.swift#L110
/// Derives a symmetric encryption key using HKDF key derivation.
///
/// - Parameters:
///   - hashFunction: The Hash Function to use for key derivation.
///   - salt: The salt to use for key derivation.
///   - sharedInfo: The Shared Info to use for key derivation.
///   - outputByteCount: The length in bytes of resulting symmetric key.
/// - Returns: The derived symmetric key
public func hkdfDerivedSymmetricKey<H: HashFunction, Salt: DataProtocol, SI: DataProtocol>(
    secret: Data,
    using hashFunction: H.Type, salt: Salt, sharedInfo: SI, outputByteCount: Int
) -> SymmetricKey {
    HKDF<H>.deriveKey(inputKeyMaterial: SymmetricKey(data: secret), salt: salt, info: sharedInfo, outputByteCount: outputByteCount)
}
