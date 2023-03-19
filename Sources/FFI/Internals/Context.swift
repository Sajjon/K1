//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation

extension Bridge {
    
    ///  Bridging type used for underlying libsecp256k1 methods:
    ///  - `secp256k1_context_create`
    ///  - `secp256k1_context_preallocated_size`
    ///  - `secp256k1_context_preallocated_create`
    enum Context: UInt32 {
        case none, sign, verify
    }
    
}
