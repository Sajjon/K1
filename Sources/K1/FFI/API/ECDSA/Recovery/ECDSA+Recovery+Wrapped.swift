import Foundation
import secp256k1


// MARK: ECDSA Recovery Wrapped
extension FFI.ECDSA.Recovery {
    final class Wrapped: @unchecked Sendable, ContiguousBytes, WrappedECDSASignature {
        typealias Raw = secp256k1_ecdsa_recoverable_signature
        var raw: Raw
        init(raw: Raw) {
            self.raw = raw
        }
    }
}

// MARK: Sign
extension FFI.ECDSA.Recovery.Wrapped {
    
    static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32 {
        secp256k1_ecdsa_sign_recoverable
    }
}

// MARK: ContiguousBytes
extension FFI.ECDSA.Recovery.Wrapped {
    
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try Swift.withUnsafeBytes(of: &raw.data) { pointer in
            try body(pointer)
        }
    }
}
