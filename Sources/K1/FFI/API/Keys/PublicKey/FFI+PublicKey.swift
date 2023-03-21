//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-20.
//

import Foundation
import secp256k1

// MARK: Deserialize
extension FFI.PublicKey {
    
    public static let x963ByteCount = 65
    public static let compactByteCount = 64
    public static let compressedByteCount = 33
    
    static func deserialize(
        x963Representation contiguousBytes: some ContiguousBytes
    ) throws -> Wrapped {
        try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
            let expected = Self.x963ByteCount
            guard bufferPointer.count == expected  else {
                throw K1.Error.incorrectByteCountOfX963PublicKey(got: bufferPointer.count, expected: expected)
            }
            return try Self._deserialize(bytes: [UInt8](bufferPointer))
        }
    }
    
    static func deserialize(
        compactRepresentation contiguousBytes: some ContiguousBytes
    ) throws -> Wrapped {
        
        try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
            let expected = Self.compactByteCount
            guard bufferPointer.count == expected  else {
                throw K1.Error.incorrectByteCountOfCompactPublicKey(got: bufferPointer.count, expected: expected)
            }
            let bytes = [UInt8](bufferPointer)
            do {
                return try Self._deserialize(bytes: bytes)
            } catch {
                // failed to parse 64 bytes => prepend with `04` and parse as `x963`
                return try Self._deserialize(bytes: [0x04] + bytes)
            }
        }
        
    }
    
    static func deserialize(
        compressedRepresentation contiguousBytes: some ContiguousBytes
    ) throws -> Wrapped {
        
        try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
            let expected = Self.compressedByteCount
            guard bufferPointer.count == expected  else {
                throw K1.Error.incorrectByteCountOfCompressedPublicKey(got: bufferPointer.count, expected: expected)
            }
            return try Self._deserialize(bytes: [UInt8](bufferPointer))
        }
        
    }
    
    private static func _deserialize(bytes: [UInt8]) throws -> Wrapped {
        var raw = secp256k1_pubkey()
        try FFI.call(
            ifFailThrow: .failedToDeserializePublicKey
        ) { context in
            secp256k1_ec_pubkey_parse(
                context,
                &raw,
                bytes,
                bytes.count
            )
            
        }
        return .init(raw: raw)
    }
}

// MARK: Serialize
extension FFI.PublicKey {
    
    static func serialize(
        _ wrapped: Wrapped,
        format: K1.Format
    ) throws -> Data {
        var byteCount = format.length
        var out = [UInt8](repeating: 0x00, count: byteCount)
        try FFI.call(ifFailThrow: .failedToSerializePublicKey) { context in
            secp256k1_ec_pubkey_serialize(
                context,
                &out,
                &byteCount,
                &wrapped.raw,
                format.rawValue
            )
        }
        return Data(out.prefix(byteCount))
    }
    
}
