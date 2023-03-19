//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation
import secp256k1

// MARK: - Curve
// MARK: -

/// Details about the elliptic curve `secp256k1`.
public enum Curve {}

// MARK: - FiniteField
// MARK: -
public extension Curve {
    /// The finite field of the secp256k1 curve.
    enum Field {}
}

public extension Curve.Field {
    /// Finite field members are 256 bits large, i.e. 32 bytes.
    static let byteCount = 32
}


extension Bridge {
    public enum ECDSA {}
}
extension Bridge.ECDSA {
    
    /// Validation mode controls whether or not signature malleability should
    /// is forbidden or allowed. Read more about it [here][more]
    ///
    /// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
    public enum ValidationMode {
        case preventSignatureMalleability
        case acceptSignatureMalleability
    }
    
    public struct SigningMode {
        public let nonceFunctionArbitraryData: Data?
        public init(nonceFunctionArbitraryData: Data? = nil) {
            self.nonceFunctionArbitraryData = nonceFunctionArbitraryData
        }
        public static let `default` = Self()
    }
    
    
    public enum Recovery {}
    public enum NonRecovery {}
}

extension Bridge.ECDSA.ValidationMode {
    public static let `default`: Self = .acceptSignatureMalleability
}

public enum RecoverableSignatureSerializationFormat {
    
    /// `R || S || V` - the format `libsecp256k1` v0.3.0 uses as internal representation
    case rsv
    
    /// `V || R || S`.
    case vrs
}

extension Bridge.ECDSA.Recovery {
    public static let byteCount = Bridge.ECDSA.NonRecovery.byteCount + 1
    public final class Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
        
        static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
            secp256k1_ecdsa_sign_recoverable
        }
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try Swift.withUnsafeBytes(of: &raw.data) { pointer in
                try body(pointer)
            }
        }
        
        typealias Raw = secp256k1_ecdsa_recoverable_signature
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
    
    public static func from(
        rawRepresentation: some DataProtocol
    ) throws -> Wrapped {
        try Wrapped(raw: Raw.recoverableSignature(rawRepresentation))
    }
    
    public static func recover(
        _ wrapped: Wrapped,
        message: [UInt8]
    ) throws -> Bridge.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var raw = secp256k1_pubkey()
        try Bridge.call(
            ifFailThrow: .failedToRecoverPublicKey
        ) { context in
            secp256k1_ecdsa_recover(context, &raw, &wrapped.raw, message)
        }
        return Bridge.PublicKey.Wrapped(raw: raw)
    }
    
    public static func serialize(
        _ wrapped: Wrapped,
        format: RecoverableSignatureSerializationFormat
    ) throws -> (rs: [UInt8], recoveryID: Int32) {
        var rs = [UInt8](repeating: 0, count: Bridge.ECDSA.NonRecovery.byteCount)
        var recoveryID: Int32 = 0
        
        try Bridge.call(
            ifFailThrow: .failedSignatureToConvertRecoverableSignatureToCompact
        ) { context in
            secp256k1_ecdsa_recoverable_signature_serialize_compact(
                context,
                &rs,
                &recoveryID,
                &wrapped.raw
            )
        }
        return (rs, recoveryID)
    }
    
    public static func nonRecoverable(
        _ wrapped: Wrapped
    ) throws -> Bridge.ECDSA.NonRecovery.Wrapped {
        
        
        var raw = secp256k1_ecdsa_signature()
        
        try Bridge.call(
            ifFailThrow: .failedToConvertRecoverableSignatureToNonRecoverable
        ) { context in
            secp256k1_ecdsa_recoverable_signature_convert(
                context,
                &raw,
                &wrapped.raw
            )
        }
        
        return .init(raw: raw)
    }
}
extension Bridge.ECDSA.NonRecovery {
    
    
    public static let byteCount = 2 * Curve.Field.byteCount
    
    public final class Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
        
        static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
            secp256k1_ecdsa_sign
        }
        
        
        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try Swift.withUnsafeBytes(of: &raw.data) { pointer in
                try body(pointer)
            }
        }
        
        typealias Raw = secp256k1_ecdsa_signature
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
    
    public static func from(
        compactBytes: [UInt8]
    ) throws -> Wrapped {
        try Wrapped(
            raw: Raw.nonRecoverableSignature(compactBytes: compactBytes)
        )
    }
    
    public static func from(
        derRepresentation: [UInt8]
    ) throws -> Wrapped {
        try Wrapped(
            raw: Raw.nonRecoverableSignature(derBytes: derRepresentation)
        )
    }
    
    public static func compact(_ wrapped: Wrapped) throws -> Data {
        
        var out = [UInt8](repeating: 0, count: Self.byteCount)
        
        try Bridge.call(ifFailThrow: .failedToSerializeSignature) { context in
            secp256k1_ecdsa_signature_serialize_compact(context, &out, &wrapped.raw)
        }
        return Data(out)
    }
    
    public static func recoverPublicKey(
        _ wrapped: Wrapped,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> Bridge.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        let nonRecoverableCompact = try Bridge.ECDSA.NonRecovery.compact(wrapped)
        return try Self.recoverPublicKey(
            nonRecoverableCompact: nonRecoverableCompact,
            recoveryID: recoveryID,
            message: message
        )
    }
    
    public static func recoverPublicKey(
        nonRecoverableCompact: Data,
        recoveryID: Int32,
        message: [UInt8]
    ) throws -> Bridge.PublicKey.Wrapped {
        guard message.count == Curve.Field.byteCount else {
            throw Bridge.Error.unableToRecoverMessageHasInvalidLength(got: message.count, expected: Curve.Field.byteCount)
        }
        var compact = [UInt8](nonRecoverableCompact)
        var recoverable = secp256k1_ecdsa_recoverable_signature()
        try Bridge.call(ifFailThrow: .failedToParseRecoverableSignatireFromCompact) { context in
            secp256k1_ecdsa_recoverable_signature_parse_compact(
                context,
                &recoverable,
                &compact,
                recoveryID
            )
        }
        var publicKeyRaw = secp256k1_pubkey()
        try Bridge.call(ifFailThrow: .failedToRecoverPublicKey) { context in
            secp256k1_ecdsa_recover(
                context,
                &publicKeyRaw,
                &recoverable,
                message
            )
        }
        return Bridge.PublicKey.Wrapped(raw: publicKeyRaw)
    }
    
    public static func der(
        _ wrapped: Wrapped
    ) throws -> Data {
        var derMaxLength = 75 // in fact max is 73, but we can have some margin.
        var derSignature = [UInt8](repeating: 0, count: derMaxLength)
        
        try Bridge.call(ifFailThrow: .failedToSerializeDERSignature) { context in
            secp256k1_ecdsa_signature_serialize_der(
                context,
                &derSignature,
                &derMaxLength,
                &wrapped.raw
            )
        }
        return Data(derSignature.prefix(derMaxLength))
    }
    
}

extension Bridge {
    public enum Scnhorr {}
}
extension Bridge.Scnhorr {
    public final class Wrapped: @unchecked Sendable, Hashable {
        public static let byteCount = 2 * Curve.Field.byteCount
        internal let bytes: [UInt8]
        
        public static func == (lhs: Wrapped, rhs: Wrapped) -> Bool {
            lhs.bytes == rhs.bytes
        }
        
        public func hash(into hasher: inout Hasher) {
            hasher.combine(bytes)
        }
        
        public var rawRepresentation: Data {
            Data(bytes)
        }
        
        
        public init(bytes: [UInt8]) throws {
            guard bytes.count == Self.byteCount else {
                throw Bridge.Error.failedToInitSchnorrSignatureInvalidByteCount(got: bytes.count, expected: Self.byteCount)
            }
            self.bytes = bytes
        }
    }
    public static func der(wrapped: Wrapped) -> [UInt8] {
        fatalError()
    }
    
    
}

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
