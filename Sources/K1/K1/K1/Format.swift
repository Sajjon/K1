//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

public extension K1 {
    
    /// Bridging type for: `secp256k1_ec_pubkey_serialize`
    enum Format: UInt32 {
        case compressed, uncompressed
    }
}

public extension K1.Format {
    
    var length: Int {
        switch self {
        case .compressed: return 33
        case .uncompressed: return 65
        }
    }
    
    init(byteCount: Int) throws {
        if byteCount == Self.uncompressed.length {
            self = .uncompressed
        } else if byteCount == Self.compressed.length {
            self = .compressed
        } else {
            throw K1.Error.incorrectByteCountOfPublicKey
        }
    }
}
