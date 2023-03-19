//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//


import CryptoKit
import secp256k1

public final class Bridge {
    
    let context: OpaquePointer
    init() throws {
        guard
            /* "Create a secp256k1 context object." */
            let context = secp256k1_context_create(Context.sign.rawValue | Bridge.Context.verify.rawValue)
        else {
            throw Bridge.Error.failedToCreateContextForSecp256k1
        }
        
        self.context = context
       
    }
    
    deinit {
        secp256k1_context_destroy(context)
    }
}

extension Bridge {
    
    public static func toC<T>(
        _ closure: (Bridge) throws -> T
    ) throws -> T {
        let bridge = try Bridge()
        return try closure(bridge)
    }
    
    /// Returns `true` iff result code is `1`
    public func validate(
        _ method: (OpaquePointer) -> Int32
    ) -> Bool {
        method(context) == 1
    }
    
    public func callWithResultCode(
        _ method: (OpaquePointer) -> Int32
    ) -> Int {
        let result = method(context)
        return Int(result)
    }
    
    public func call(
        ifFailThrow error: Bridge.Error,
        _ method: (OpaquePointer) -> Int32
    ) throws {
      let result = callWithResultCode(method)
        let successCode = 1
        guard result == successCode else {
            throw error
        }
    }
    
    public static func call(
        ifFailThrow error: Bridge.Error,
        _ method: (OpaquePointer) -> Int32
    ) throws {
        try toC { bridge in
            try bridge.call(ifFailThrow: error, method)
        }
    }
}
