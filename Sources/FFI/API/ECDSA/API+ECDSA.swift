//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation

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
