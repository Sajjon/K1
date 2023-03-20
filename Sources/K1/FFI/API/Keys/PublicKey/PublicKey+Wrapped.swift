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

// MARK: Serialize
extension FFI.PublicKey.Wrapped {
    func rawRepresentation(format: K1.Format) throws -> Data {
        var byteCount = format.length
        var out = [UInt8](repeating: 0x00, count: byteCount)
        try FFI.call(ifFailThrow: .failedToSerializePublicKey) { context in
            secp256k1_ec_pubkey_serialize(
                context,
                &out,
                &byteCount,
                &raw,
                format.rawValue
            )
        }
        return Data(out.prefix(byteCount))
    }
}


// MARK: Deserialize
extension FFI.PublicKey {
   
    public static let x963ByteCount = 65
    public static let compactByteCount = 64
    public static let compressedByteCount = 33
   
    static func from(x963Representation contiguousBytes: some ContiguousBytes) throws -> Wrapped {
        try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
            let expected = Self.x963ByteCount
            guard bufferPointer.count == expected  else {
                throw K1.Error.incorrectByteCountOfX963PublicKey(got: bufferPointer.count, expected: expected)
            }
            return try Self.from(bytes: [UInt8](bufferPointer))
        }
    }
    
    static func from(compactRepresentation contiguousBytes: some ContiguousBytes) throws -> Wrapped {
        
        try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
            let expected = Self.compactByteCount
            guard bufferPointer.count == expected  else {
                throw K1.Error.incorrectByteCountOfCompactPublicKey(got: bufferPointer.count, expected: expected)
            }
            let bytes = [UInt8](bufferPointer)
            do {
                return try Self.from(bytes: bytes)
            } catch {
                // failed to parse 64 bytes => prepend with `04` and parse as `x963`
                return try Self.from(bytes: [0x04] + bytes)
            }
        }
        
    }
    
    static func from(compressedRepresentation contiguousBytes: some ContiguousBytes) throws -> Wrapped {
        
        try contiguousBytes.withUnsafeBytes { bufferPointer throws -> Wrapped in
            let expected = Self.compressedByteCount
            guard bufferPointer.count == expected  else {
                throw K1.Error.incorrectByteCountOfCompressedPublicKey(got: bufferPointer.count, expected: expected)
            }
            return try Self.from(bytes: [UInt8](bufferPointer))
        }
        
        
    }
    
    internal static func from(bytes: [UInt8]) throws -> Wrapped {
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

