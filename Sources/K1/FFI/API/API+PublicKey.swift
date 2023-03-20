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
extension FFI.PublicKey {
    
    final class Wrapped: @unchecked Sendable, ContiguousBytes {
        typealias Raw = secp256k1_pubkey
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
}

extension FFI.PublicKey.Wrapped {
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: &raw.data) { pointer in
            try body(pointer)
        }
    }
    
    func compare(to other: FFI.PublicKey.Wrapped) throws -> Bool {
        return try FFI().callWithResultCode { context in
            secp256k1_ec_pubkey_cmp(context, &self.raw, &other.raw)
        } == 0
    }
    
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
    
    func isValid(
        schnorrSignature: FFI.Scnhorr.Wrapped,
        message: [UInt8]
    ) throws -> Bool {
        return try FFI.toC { ffi -> Bool in
            var publicKeyX = secp256k1_xonly_pubkey()
            
            try FFI.call(ifFailThrow: .failedToSchnorrVerifyGettingXFromPubKey) { context in
                secp256k1_xonly_pubkey_from_pubkey(context, &publicKeyX, nil, &self.raw)
            }
            return ffi.validate { context in
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
    
    func isValid(
        ecdsaSignature: FFI.ECDSA.NonRecovery.Wrapped,
        message: [UInt8],
        mode: K1.ECDSA.ValidationMode
    ) throws -> Bool {
        try FFI.toC { ffi -> Bool in
            var maybeMalleable = ecdsaSignature.raw
            var normalized = secp256k1_ecdsa_signature()
            
            let codeForSignatureWasMalleable = 1
            let signatureWasMalleableResult = ffi.callWithResultCode { context in
                secp256k1_ecdsa_signature_normalize(context, &normalized, &maybeMalleable)
            }
            let signatureWasMalleable = signatureWasMalleableResult == codeForSignatureWasMalleable
            let isSignatureValid = ffi.validate { context in
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
    
}
    
extension FFI.PublicKey {
    static func from(x963Representation bytes: some ContiguousBytes) throws -> Wrapped {
        try Self.from(bytes: bytes)
    }
    
    internal static func from(bytes contiguousBytes: some ContiguousBytes) throws -> Wrapped {
        return try contiguousBytes.withUnsafeBytes { bytes throws -> Wrapped in
            guard K1.Format.allCases.map(\.length).contains(bytes.count) else {
                throw K1.Error.incorrectByteCountOfPublicKey(providedByteCount: bytes.count)
            }
            var raw = secp256k1_pubkey()
            try FFI.call(
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
}

