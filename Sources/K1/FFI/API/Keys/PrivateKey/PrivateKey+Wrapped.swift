//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-18.
//

import Foundation
import secp256k1

extension FFI {
    enum PrivateKey {
        final class Wrapped: @unchecked Sendable {
            
            let publicKey: FFI.PublicKey.Wrapped
            internal let secureBytes: SecureBytes
            
            fileprivate init(secureBytes: SecureBytes) throws {
                guard secureBytes.count == Curve.Field.byteCount else {
                    throw K1.Error.failedToInitializePrivateKeyIncorrectByteCount(
                        got: secureBytes.count,
                        expected: Curve.Field.byteCount
                    )
                }
                
                if secureBytes.allSatisfy({ $0 == .zero }) {
                    throw K1.Error.invalidPrivateKeyMustNotBeZero
                }
                
                self.secureBytes = secureBytes
                var secureBytes = secureBytes
                self.publicKey = try secureBytes.withUnsafeMutableBytes { seckey in
                    var raw = secp256k1_pubkey()
                    
                    try FFI.call(ifFailThrow: .invalidPrivateKeyMustBeSmallerThanOrder) { context in
                        secp256k1_ec_pubkey_create(context, &raw, seckey.baseAddress!)
                    }
                    
                    return FFI.PublicKey.Wrapped(raw: raw)
                }
            }
        }
    }
}

// MARK: Init
extension FFI.PrivateKey.Wrapped {
    
    fileprivate convenience init(bytes: [UInt8]) throws {
        try self.init(secureBytes: .init(bytes: bytes))
    }
    
    convenience init() {
        func generateNew() -> SecureBytes {
            var attempt = 0
            
            while attempt < 100 {
                defer { attempt += 1 }
                do {
                    let secureBytes = SecureBytes(count: Curve.Field.byteCount)
                    let _ = try FFI.PrivateKey.Wrapped(secureBytes: secureBytes)
                    return secureBytes
                } catch {
                    // Failure (due to unlikely scenario that the private key scalar > order of the curve) => retry
                }
            }
            
            // Probability of this happening is:
            // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            // (n / 2^256) ^ 100 = lim 0
            // I.e. will not happen.
            fatalError(
                """
                Failed to generate private key after #\(attempt) attempts.
                You are the most unlucky person in the universe.
                Or by Occam's razor: the person writing this code made some error.
                """
            )
        }
        try! self.init(secureBytes: generateNew())
    }
}

// MARK: Deserialize
extension FFI.PrivateKey {
    static func from(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(bytes: [UInt8](rawRepresentation))
    }
}
