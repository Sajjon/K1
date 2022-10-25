//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//



public struct ECDSASignatureRecoverable: ContiguousBytes, Sendable, Hashable, ECSignature {
    
    private let _rawRepresentation: [UInt8]

    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
       
        guard
            rawRepresentation.count == Self.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self._rawRepresentation = [UInt8](rawRepresentation)
    }
}


private extension ECDSASignatureRecoverable {
    static let byteCount = ECDSASignatureNonRecoverable.byteCount + 1
}

public extension ECDSASignatureRecoverable {
    
    var rawRepresentation: Data {
        Data(_rawRepresentation)
    }
    
    var rs: [UInt8] {
        [UInt8](bytes.prefix(64))
    }
    
    /// aka Signature `v`, aka `recid`
    var recoveryID: Int32 { Int32(bytes[64]) }

    
    typealias Scheme = ECDSA
    static let scheme: SigningScheme = .ecdsa
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.rawRepresentation.withUnsafeBytes(body)
    }
    
    func nonRecoverable() throws -> ECDSASignatureNonRecoverable {
        try Bridge.convertToNonRecoverable(ecdsaSignature: self)
    }
    
}

public typealias ECDSASignature = ECDSASignatureNonRecoverable

public struct ECDSASignatureNonRecoverable: ContiguousBytes, Sendable, Hashable, ECSignature {
    
    public typealias Scheme = ECDSA
   
    private let _rawRepresentation: [UInt8]
    public var rawRepresentation: Data {
        Data(_rawRepresentation)
    }
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
       
        guard
            rawRepresentation.count == Self.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self._rawRepresentation = [UInt8](rawRepresentation)
    }
}

private extension ECDSASignatureNonRecoverable {
    static let byteCount = 2 * K1.Curve.Field.byteCount
}

public extension ECDSASignatureNonRecoverable {
    static let scheme: SigningScheme = .ecdsa
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.rawRepresentation.withUnsafeBytes(body)
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
