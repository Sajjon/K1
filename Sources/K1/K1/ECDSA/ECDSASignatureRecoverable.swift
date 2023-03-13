//
//  File.swift
//
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import CryptoKit

public struct ECDSASignatureRecoverable: Sendable, Hashable, ECSignature {
    
    /// `R||S` (64 bytes), without the recovery id
    public let rs: Data
    
    public let recoveryID: Int32
    
    public init(rs: Data, recoveryID: Int32) throws {
        guard
             rs.count == ECDSASignatureNonRecoverable.byteCount
         else {
             throw K1.Error.incorrectByteCountOfRawSignature
         }
        self.rs = rs
        self.recoveryID = recoveryID
    }
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {

        guard
            rawRepresentation.count == ECDSASignatureNonRecoverable.byteCount + 1
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        let rsV = [UInt8](rawRepresentation)
        try self.init(rs: Data(rsV.prefix(64)), recoveryID: Int32(rsV[64]))
    }
}


//private extension ECDSASignatureRecoverable {
//    static let byteCount = ECDSASignatureNonRecoverable.byteCount + 1
//}

public extension ECDSASignatureRecoverable {
    
//    func rs() -> Data {
//        Data(rawRepresentation.suffix(64))
//    }
//
//    /// aka Signature `v`, aka `recid`
//    var recoveryID: Int { Int(rawRepresentation[0]) }
    
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
        
    func wasSigned<D>(by signer: K1.PublicKey, for digest: D) throws -> Bool where D : Digest {
        try nonRecoverable().wasSigned(by: signer, for: digest)
    }

}
