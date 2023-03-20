//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

// MARK: ECDSA Non-Recoverable
extension K1.PrivateKey {
    public func ecdsaSignNonRecoverable(
        digest: some Digest,
        mode: K1.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        try ECDSASignatureNonRecoverable(
            wrapped: FFI.ECDSA.NonRecovery.sign(
                hashedMessage: [UInt8](digest),
                privateKey: wrapped,
                mode: mode
            )
        )
    }
    
    /// SHA256 hashes `unhashed` before signing it.
    public func ecdsaSignNonRecoverable(
        unhashed: some DataProtocol,
        mode: K1.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureNonRecoverable {
        try ecdsaSignNonRecoverable(digest: SHA256.hash(data: unhashed), mode: mode)
    }
}
