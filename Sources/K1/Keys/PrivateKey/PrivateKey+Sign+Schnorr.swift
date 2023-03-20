//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest
import struct CryptoKit.SHA256

// MARK: Schnorr Sign
extension K1.PrivateKey {
    
    public func schnorrSign(
        hashed: some DataProtocol,
        input: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try SchnorrSignature(
            wrapped: FFI.Schnorr.sign(
                hashedMessage: [UInt8](hashed),
                privateKey: wrapped,
                input: input
            )
        )
    }
    
    public func schnorrSign(
        digest: some Digest,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try schnorrSign(
            hashed: [UInt8](digest),
            input: maybeInput
        )
    }
    
    /// SHA256 hashes `unhashed` before signing it.
    public func schnorrSign(
        unhashed: some DataProtocol,
        input maybeInput: SchnorrInput? = nil
    ) throws -> SchnorrSignature {
        try schnorrSign(
            digest: SHA256.hash(data: unhashed),
            input: maybeInput
        )
    }

}


