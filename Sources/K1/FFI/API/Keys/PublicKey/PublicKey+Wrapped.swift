//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension FFI {
    enum PublicKey {}
}

// MARK: PublicKey Wrapped
extension FFI.PublicKey {
    
    final class Wrapped: @unchecked Sendable, ContiguousBytes {
        typealias Raw = secp256k1_pubkey
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
}

// MARK: ContiguousBytes
extension FFI.PublicKey.Wrapped {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: &raw.data) { pointer in
            try body(pointer)
        }
    }
}

// MARK: Comparison
extension FFI.PublicKey.Wrapped {
    func compare(to other: FFI.PublicKey.Wrapped) throws -> Bool {
        return try FFI().callWithResultCode { context in
            secp256k1_ec_pubkey_cmp(context, &self.raw, &other.raw)
        } == 0
    }
}

