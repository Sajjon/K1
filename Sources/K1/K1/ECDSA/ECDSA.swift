//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-24.
//

import Foundation


extension K1 {
    
    /// A mechanism used to create or verify a cryptographic signature using the `secp256k1` elliptic curve digital signature algorithm (ECDSA).
    public enum ECDSA {}
}

extension K1.ECDSA {
    public struct ValidationOptions {
        
        public let malleabilityStrictness: MalleabilityStrictness
        
        public init(malleabilityStrictness: MalleabilityStrictness) {
            self.malleabilityStrictness = malleabilityStrictness
        }
      
    }
}

extension K1.ECDSA.ValidationOptions {
    
    public static let `default`: Self = .init(
        malleabilityStrictness: .rejected
    )
    
    /// Whether or not to consider malleable signatures valid.
    ///
    /// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
    public enum MalleabilityStrictness {
        /// Considers all malleable signatures **invalid**.
        case rejected
        
        /// Accepts malleable signatures valid.
        case accepted
    }
}

// MARK: SigningOptions
extension K1.ECDSA {
    public struct SigningOptions: Sendable, Hashable {
        public let nonceFunction: NonceFunction

        public init(nonceFunction: NonceFunction) {
            self.nonceFunction = nonceFunction
        }
    }
}

extension K1.ECDSA.SigningOptions {
    
    public static let `default`: Self = .init(nonceFunction: .deterministic())
    
    public enum NonceFunction: Sendable, Hashable {
        case random
        
        /// RFC6979
        case deterministic(arbitraryData: RFC6979ArbitraryData? = nil)
    }
}

extension K1.ECDSA.SigningOptions.NonceFunction {
    public struct RFC6979ArbitraryData: Sendable, Hashable {
        public let arbitraryData: [UInt8]
        public init(arbitraryData: [UInt8]) throws {
            guard arbitraryData.count == Curve.Field.byteCount else {
                throw K1.Error.incorrectByteCountOfArbitraryDataForNonceFunction
            }
            self.arbitraryData = arbitraryData
        }
    }
}
