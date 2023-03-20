//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

// MARK: ECDSA Recoverable
extension K1.PrivateKey {
    public func ecdsaSignRecoverable(
        hashed hashedMessage: some DataProtocol,
        mode: K1.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ECDSASignatureRecoverable(
            wrapped: FFI.ECDSA.Recovery.sign(
                hashedMessage: [UInt8](hashedMessage),
                privateKey: wrapped,
                mode: mode
            )
        )
    }
    
    public func ecdsaSignRecoverable(
        digest: some Digest,
        mode: K1.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ecdsaSignRecoverable(
            hashed: Data(digest),
            mode: mode
        )
    }
    
    /// SHA256 hashes `unhashed` before signing it.
    public func ecdsaSignRecoverable(
        unhashed: some DataProtocol,
        mode: K1.ECDSA.SigningMode = .default
    ) throws -> ECDSASignatureRecoverable {
        try ecdsaSignRecoverable(
            digest: SHA256.hash(data: unhashed),
            mode: mode
        )
    }
}
