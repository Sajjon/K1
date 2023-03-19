//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation
import FFI
import CryptoKit

public extension K1 {
    
    struct PublicKey: Sendable, Hashable {
        
        public static func == (lhsSelf: Self, rhsSelf: Self) -> Bool {
            let lhs = lhsSelf.wrapped
            let rhs = rhsSelf.wrapped
            do {
                return try lhs.compare(to: rhs)
            } catch {
                return lhs.withUnsafeBytes { lhsBytes in
                    rhs.withUnsafeBytes { rhsBytes in
                        safeCompare(lhsBytes, rhsBytes)
                    }
                }
            }
        }
        public func hash(into hasher: inout Hasher) {
            wrapped.withUnsafeBytes {
                hasher.combine(bytes: $0)
            }
        }
        
        typealias Wrapped = Bridge.PublicKey.Wrapped
        internal let wrapped: Wrapped

        internal init(wrapped: Wrapped) {
            self.wrapped = wrapped
        }
        
        public init(x963Representation: some ContiguousBytes) throws  {
            try self.init(wrapped: Bridge.PublicKey.from(x963Representation: x963Representation))
        }
        
        public func rawRepresentation(format: Bridge.Format) throws -> Data {
            try wrapped.rawRepresentation(format: format)
        }
        
        public func isValidECDSASignature(
            _ signature: ECDSASignatureNonRecoverable,
            hashed: some DataProtocol,
            mode: SignatureValidationMode = .default
        ) -> Bool {
            do {
                return try wrapped.isValid(ecdsaSignature: signature.wrapped, message: [UInt8](hashed), mode: mode)
            } catch {
                return false
            }
        }
        
        public func isValidECDSASignature(
            _ signature: ECDSASignatureNonRecoverable,
            digest: some Digest,
            mode: SignatureValidationMode = .default
        ) -> Bool {
            isValidECDSASignature(signature, hashed: Data(digest), mode: mode)
        }
        
        /// `SHA256` hashes `unhashed` bore calling `isValidECDSASignature`
        public func isValidECDSASignature(
            _ signature: ECDSASignatureNonRecoverable,
            unhashed: some DataProtocol,
            mode: SignatureValidationMode = .default
        ) -> Bool {
            isValidECDSASignature(signature, digest: SHA256.hash(data: unhashed), mode: mode)
        }
        
        // MARK: Recoverable
        public func isValidECDSASignature(
            _ signature: ECDSASignatureRecoverable,
            hashed: some DataProtocol,
            mode: SignatureValidationMode = .default
        ) -> Bool {
            do {
               return try isValidECDSASignature(signature.nonRecoverable(), hashed: hashed, mode: mode)
            } catch {
                return false
            }
        }
        
        public func isValidECDSASignature(
            _ signature: ECDSASignatureRecoverable,
            digest: some Digest,
            mode: SignatureValidationMode = .default
        ) -> Bool {
            do {
               return try isValidECDSASignature(signature.nonRecoverable(), digest: digest, mode: mode)
            } catch {
                return false
            }
        }
        
        /// `SHA256` hashes `unhashed` bore calling `isValidECDSASignature`
        public func isValidECDSASignature(
            _ signature: ECDSASignatureRecoverable,
            unhashed: some DataProtocol,
            mode: SignatureValidationMode = .default
        ) -> Bool {
            do {
               return try isValidECDSASignature(signature.nonRecoverable(), unhashed: unhashed, mode: mode)
            } catch {
                return false
            }
        }
        
        
    }
}


// MARK: - Convenience Init
// MARK: -
public extension K1.PublicKey {
    
    static func `import`(
        from data: some DataProtocol
    ) throws -> Self {
//        try self.init(
//            wrapped: (from: [UInt8](data))
//        )
        fatalError()
    }
    
}
