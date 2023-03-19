//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation

extension Bridge {
    /// Bridging type for: `secp256k1_ec_pubkey_serialize`
    public enum Format: UInt32, CaseIterable {
        case compressed, uncompressed
    }
}

extension Bridge.Format {
    
    public var length: Int {
        switch self {
        case .compressed: return 33
        case .uncompressed: return 65
        }
    }
    
    public init(byteCount: Int) throws {
        if byteCount == Self.uncompressed.length {
            self = .uncompressed
        } else if byteCount == Self.compressed.length {
            self = .compressed
        } else {
            throw Bridge.Error.incorrectByteCountOfPublicKey(providedByteCount: byteCount)
        }
    }
}
