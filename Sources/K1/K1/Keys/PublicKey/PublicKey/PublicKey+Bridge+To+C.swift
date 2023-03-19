//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//


// Bridge to C
import FFI
import CryptoKit
import Foundation

// MARK: - Validate (Verify)
// MARK: -
internal extension K1.PublicKey {
    
    func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        hashed: some DataProtocol
    ) throws -> Bool {
        do {
            return try wrapped.isValid(schnorrSignature: signature.wrapped, message: [UInt8](hashed))
        } catch {
            return false
        }
    }
    
 
}



// MARK: - Validate Schnorr (Verify)
// MARK: -
public extension K1.PublicKey {
    
    func isValidSchnorrSignature<D: Digest>(
        _ signature: SchnorrSignature,
        digest: D
    ) throws -> Bool {
        try isValidSchnorrSignature(signature, hashed: Data(digest))
    }
    
    func isValidSchnorrSignature<M: DataProtocol>(
        _ signature: SchnorrSignature,
        unhashed: M
    ) throws -> Bool {
        try isValidSchnorrSignature(signature, digest: SHA256.hash(data: unhashed))
    }
}

