//
//  File.swift
//
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit
import secp256k1

public struct ECDSASignatureRecoverable: Sendable, Hashable, ECSignature {
 
    public let rawRepresentation: Data
    
    public init(compactRepresentation: Data, recoveryID: Int32) throws {
        guard
            compactRepresentation.count == ECDSASignatureNonRecoverable.byteCount
         else {
             throw K1.Error.incorrectByteCountOfRawSignature
         }
        var recoverableSignature = secp256k1_ecdsa_recoverable_signature()
        let rs = [UInt8](compactRepresentation)
  
        try Bridge.call(ifFailThrow: .failedToParseRecoverableSignatureFromCompactRepresentation) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &recoverableSignature,
                rs,
                recoveryID
            )
        }
        self.rawRepresentation = Data(
            bytes: &recoverableSignature.data,
            count: MemoryLayout.size(ofValue: recoverableSignature.data)
        )
    }

    public init<D: DataProtocol>(rawRepresentation: D) throws {

        guard
            rawRepresentation.count == ECDSASignatureNonRecoverable.byteCount + 1
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        self.rawRepresentation = Data(rawRepresentation)
    }
    
    
}

public extension ECDSASignatureRecoverable {
    
    typealias Scheme = ECDSA
    static let scheme: SigningScheme = .ecdsa
    
    func nonRecoverable() throws -> ECDSASignatureNonRecoverable {
        try Bridge.convertToNonRecoverable(ecdsaSignature: self)
    }
    
    func compact() throws -> (rs: Data, recoveryID: Int) {
        var rsBytes = [UInt8](repeating: 0, count: 64)
        var recoveryID: Int32 = 0
        
        var recoverableBridgedToC = secp256k1_ecdsa_recoverable_signature()
        withUnsafeMutableBytes(of: &recoverableBridgedToC.data) { pointer in
            pointer.copyBytes(
                from: rawRepresentation.prefix(pointer.count)
            )
        }
        
        try Bridge.call(
            ifFailThrow: .failedSignatureToConvertRecoverableSignatureToCompact) { context in
                secp256k1_ecdsa_recoverable_signature_serialize_compact(
                context,
                &rsBytes,
                &recoveryID,
                &recoverableBridgedToC
            )
        }
        return (rs: Data(rsBytes), recoveryID: Int(recoveryID))
    }
    
}

public extension ECDSASignatureRecoverable {
    typealias ValidationMode = ECDSASignatureNonRecoverable.ValidationMode
    typealias SigningMode = ECDSASignatureNonRecoverable.SigningMode
   
    func wasSigned<D>(by signer: K1.PublicKey, for digest: D, mode: ValidationMode) throws -> Bool where D : Digest {
        try nonRecoverable().wasSigned(by: signer, for: digest, mode: mode)
    }
    
    func wasSigned<D>(by signer: K1.PublicKey, hashedMessage: D, mode: ValidationMode) throws -> Bool where D : DataProtocol {
        try nonRecoverable().wasSigned(by: signer, hashedMessage: hashedMessage, mode: mode)
    }
    
    static func by<D>(signing hashed: D, with privateKey: K1.PrivateKey, mode: SigningMode) throws -> Self where D : DataProtocol {
        try privateKey.ecdsaSignRecoverable(hashed: hashed, mode: mode)
    }
        
    func wasSigned<D>(by signer: K1.PublicKey, for digest: D) throws -> Bool where D : Digest {
        try nonRecoverable().wasSigned(by: signer, for: digest)
    }

}
