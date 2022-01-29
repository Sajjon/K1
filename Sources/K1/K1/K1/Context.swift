//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

internal extension K1 {
    
    ///  Bridging type used for underlying libsecp256k1 methods:
    ///  - `secp256k1_context_create`
    ///  - `secp256k1_context_preallocated_size`
    ///  - `secp256k1_context_preallocated_create`
    enum Context: UInt32 {
        case none, sign, verify
    }
}
