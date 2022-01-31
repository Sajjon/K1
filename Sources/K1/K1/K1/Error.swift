//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//

import Foundation

public extension K1 {
    
    enum Error: Swift.Error {
        
        /// The private key scalar was either 0 or larger then the order of the
        /// curve.
        case invalidPrivateKeyNotWithinBounds

        case incorrectByteCountOfPrivateKey
        case incorrectByteCountOfPublicKey
        
        case incorrectByteCountOfRawSignature
        
        case failedToCreateContextForSecp256k1
        case failedToUpdateContextRandomization
        case failedToComputePublicKeyFromPrivateKey
        case failedToSerializePublicKeyIntoBytes
        
        case failedToParseDERSignature
        case failedToSerializeCompactSignature
        case failedToSerializeDERSignature
        case failedToSignDigest
        case failedToPerformDiffieHellmanKeyExchange
    }

}
