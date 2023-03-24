//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation

// MARK: Recovery
extension ECDSASignatureRecoverable {
    
    public enum RecoveryID: UInt8, Sendable, Hashable, Codable {
        case _0 = 0
        case _1 = 1
        case _2 = 2
        case _3 = 3
        
        internal var recid: Int32 {
            Int32(rawValue)
        }
    }
}

extension ECDSASignatureRecoverable.RecoveryID {
    public init(byte: UInt8) throws {
        guard let self_ = Self(rawValue: byte) else {
            throw K1.Error.invalidRecoveryID(got: Int(byte))
        }
        self = self_
    }
    
    public init(recid: Int32) throws {
        guard recid <= 3 && recid >= 0 else {
            throw K1.Error.invalidRecoveryID(got: Int(recid))
        }
        try self.init(byte: UInt8(recid))
    }
}
