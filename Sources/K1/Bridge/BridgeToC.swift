//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//

import Foundation

import Crypto // swift-crypto
import secp256k1

internal final class Bridge {
    
    let context: OpaquePointer
    init() throws {
        guard
            /* "Create a secp256k1 context object." */
            let context = secp256k1_context_create(K1.Context.sign.rawValue | K1.Context.verify.rawValue)
        else {
            throw K1.Error.failedToCreateContextForSecp256k1
        }
        
        self.context = context
       
    }
    
    deinit {
        secp256k1_context_destroy(context)
    }
}

extension Bridge {
    
    static func toC<T>(
        _ closure: (Bridge) throws -> T
    ) throws -> T {
        let bridge = try Bridge()
        return try closure(bridge)
    }
    
    func call(
        ifFailThrow error: K1.Error,
        _ method: (OpaquePointer) -> Int32
    ) throws {
        let result = method(context)
        
        let successCode: Int32 = 1
        
        guard result == successCode else {
            throw error
        }
    }
    
    static func call(
        ifFailThrow error: K1.Error,
        _ method: (OpaquePointer) -> Int32
    ) throws {
        try toC { bridge in
            try bridge.call(ifFailThrow: error, method)
        }
    }
}
