//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

// FFI to C
import secp256k1

// MARK: Context
extension FFI.Context {
    
    /// Bridging value used by libsecp256k1 methods that requires info about
    /// how the context is used, e.g. for signing or verification (validate).
    var rawValue: UInt32 {
        let value: Int32

        switch self {
            case .none: value = SECP256K1_CONTEXT_NONE
            case .sign: value = SECP256K1_CONTEXT_SIGN
            case .verify: value = SECP256K1_CONTEXT_VERIFY
        }

        return UInt32(value)
    }
}

// MARK: Format
extension K1.Format {
    
    /// Bridging value used by libsecp256k1 key specifying the format
    /// of the imported key, i.e. how many bytes.
    public var rawValue: UInt32 {
        let value: Int32
        switch self {
        case .compressed: value = SECP256K1_EC_COMPRESSED
        case .uncompressed: value = SECP256K1_EC_UNCOMPRESSED
        }
        
        return UInt32(value)
    }
}
