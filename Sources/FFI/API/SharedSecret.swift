//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation

// MUST match https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Agreement/DH.swift#L34
import struct CryptoKit.SharedSecret

/// A Key Agreement Result
/// A SharedSecret has to go through a Key Derivation Function before being able to use by a symmetric key operation.
@_spi(Internals)
public struct __SharedSecret {
    var ss: SecureBytes
    
    internal init(ss: SecureBytes) {
        self.ss = ss
    }
}


extension CryptoKit.SharedSecret {
    @_spi(Internals)
    public init(data: Data) throws {
        let __sharedSecret = __SharedSecret(ss: .init(bytes: data))
        let sharedSecret = unsafeBitCast(__sharedSecret, to: SharedSecret.self)
        guard sharedSecret.withUnsafeBytes({ Data($0).count == data.count }) else {
            throw Bridge.Error.failedToProduceSharedSecret
        }
        
        self = sharedSecret
    }
}
