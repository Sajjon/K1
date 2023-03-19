//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation
import secp256k1


extension Bridge {
    public enum PublicKey {}
}
extension Bridge.PublicKey {
    
    public static func from(x963Representation bytes: some ContiguousBytes) throws -> Wrapped {
        try Self.from(bytes: bytes)
    }
    
    internal static func from(bytes contiguousBytes: some ContiguousBytes) throws -> Wrapped {
        return try contiguousBytes.withUnsafeBytes { bytes throws -> Wrapped in
            guard Bridge.Format.allCases.map(\.length).contains(bytes.count) else {
                throw Bridge.Error.incorrectByteCountOfPublicKey(providedByteCount: bytes.count)
            }
            var raw = secp256k1_pubkey()
            try Bridge.call(
                ifFailThrow: .failedToDeserializePublicKey
            ) { context in
                secp256k1_ec_pubkey_parse(
                    context,
                    &raw,
                    bytes.baseAddress!,
                    bytes.count
                )
            }
            return .init(raw: raw)
        }
    }
    
    public final class Wrapped: @unchecked Sendable, ContiguousBytes {
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try Swift.withUnsafeBytes(of: &raw.data) { pointer in
                try body(pointer)
            }
        }
        public func compare(to other: Wrapped) throws -> Bool {
            return try Bridge().callWithResultCode { context in
                secp256k1_ec_pubkey_cmp(context, &self.raw, &other.raw)
            } == 0
        }
        
        public func rawRepresentation(format: Bridge.Format) throws -> Data {
            var byteCount = format.length
            var out = [UInt8](repeating: 0x00, count: byteCount)
            try Bridge.call(ifFailThrow: .failedToSerializePublicKey) { context in
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
        
        public func isValid(
            schnorrSignature: Bridge.Scnhorr.Wrapped,
            message: [UInt8]
        ) throws -> Bool {
            return try Bridge.toC { bridge -> Bool in
                var publicKeyX = secp256k1_xonly_pubkey()
                
                try bridge.call(ifFailThrow: .failedToSchnorrVerifyGettingXFromPubKey) { context in
                    secp256k1_xonly_pubkey_from_pubkey(context, &publicKeyX, nil, &self.raw)
                }
                return bridge.validate { context in
                    secp256k1_schnorrsig_verify(
                        context,
                        schnorrSignature.bytes,
                        message,
                        message.count,
                        &publicKeyX
                    )
                }
            }
        }
        
        public func isValid(
            ecdsaSignature: Bridge.ECDSA.NonRecovery.Wrapped,
            message: [UInt8],
            mode: Bridge.ECDSA.ValidationMode
        ) throws -> Bool {
            try Bridge.toC { bridge -> Bool in
                var maybeMalleable = ecdsaSignature.raw
                var normalized = secp256k1_ecdsa_signature()
                
                let codeForSignatureWasMalleable = 1
                let signatureWasMalleableResult = bridge.callWithResultCode { context in
                    secp256k1_ecdsa_signature_normalize(context, &normalized, &maybeMalleable)
                }
                let signatureWasMalleable = signatureWasMalleableResult == codeForSignatureWasMalleable
                let isSignatureValid = bridge.validate { context in
                    secp256k1_ecdsa_verify(
                        context,
                        &normalized,
                        message,
                        &self.raw
                    )
                }
                let acceptMalleableSignatures = mode == .acceptSignatureMalleability
                switch (isSignatureValid, signatureWasMalleable, acceptMalleableSignatures) {
                case (true, false, _):
                    // Signature is valid
                    return true
                case (true, true, true):
                    // Signature was valid but malleable, since you specified to
                    // accept malleability => considering signature valid.
                    return true
                case (true, true, false):
                    // Signature was valid, but not normalized which was required =>
                    // considering signature invalid.
                    return false
                case (false, _, _):
                    // Signature is invalid.
                    return false
                }
            }
        }
        
        typealias Raw = secp256k1_pubkey
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
        
        
    }
    
}


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
