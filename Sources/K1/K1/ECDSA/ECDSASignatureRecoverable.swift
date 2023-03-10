//
//  File.swift
//
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

public struct ECDSASignatureRecoverable: Sendable, Hashable, ECSignature {
    
    internal let _rawRepresentation: Data
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
       
        guard
            rawRepresentation.count == Self.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self._rawRepresentation = Data(rawRepresentation)
    }
}


private extension ECDSASignatureRecoverable {
    static let byteCount = ECDSASignatureNonRecoverable.byteCount + 1
}

public extension ECDSASignatureRecoverable {
    
    /// `R||S` without `V`
    func rs() -> Data {
        Data(_rawRepresentation.prefix(64))
    }
    
    /// aka Signature `v`, aka `recid`
    var recoveryID: Int { Int(_rawRepresentation[64]) }
    
    typealias Scheme = ECDSA
    static let scheme: SigningScheme = .ecdsa
    
    func nonRecoverable() throws -> ECDSASignatureNonRecoverable {
        try Bridge.convertToNonRecoverable(ecdsaSignature: self)
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
    
//    /// Tosses away V byte
//    func compactRepresentation() throws -> Data {
//
//    }
//
//    func derRepresentation() throws -> Data {
//        fatalError()
//    }
    
    func wasSigned<D>(by signer: K1.PublicKey, for digest: D) throws -> Bool where D : Digest {
        try nonRecoverable().wasSigned(by: signer, for: digest)
    }

}
