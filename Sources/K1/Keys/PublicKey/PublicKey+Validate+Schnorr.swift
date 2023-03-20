//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import protocol CryptoKit.Digest

// MARK: Validate Schnorr Signatures
extension K1.PublicKey {
    
    
    public func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        hashed: some DataProtocol
    ) -> Bool {
        do {
            return try wrapped.isValid(
                schnorrSignature: signature.wrapped,
                message: [UInt8](hashed)
            )
        } catch {
            return false
        }
    }
    
    public func isValidSchnorrSignature(
        _ signature: SchnorrSignature,
        digest: some Digest
    ) -> Bool {
        isValidSchnorrSignature(
            signature,
            hashed: [UInt8](digest)
        )
    }

}
