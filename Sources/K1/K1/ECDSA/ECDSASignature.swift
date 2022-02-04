//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


public struct ECDSASignature: ContiguousBytes, Equatable, ECSignature {

    public var rawRepresentation: Data
    
    public init<D: DataProtocol>(rawRepresentation: D) throws {
        guard
            rawRepresentation.count == 2 * K1.Curve.Field.byteCount
        else {
            throw K1.Error.incorrectByteCountOfRawSignature
        }
        
        self.rawRepresentation = Data(rawRepresentation)
    }
}

public extension ECDSASignature {
    static let scheme: Scheme = .ecdsa
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try self.rawRepresentation.withUnsafeBytes(body)
    }
    
}
