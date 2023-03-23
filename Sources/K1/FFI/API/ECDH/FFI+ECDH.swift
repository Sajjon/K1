//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-19.
//

import Foundation
import secp256k1

extension FFI {
    
    /// Just a namespace for `FFI ECDH` 
    enum ECDH  {}
}

// MARK: SerializeFunction
extension FFI.ECDH {
    
    enum SerializeFunction {
        
        /// Using the `libsecp256k1` default behaviour.
        ///
        /// SHA256 hashes the **compressed** shared point.
        /// Accepts arbitrary data passed through hash function as well.
        ///
        case libsecp256kDefault(arbitraryData: Data?)
        
        /// Following the [ANSI X9.63][ansix963] standard
        ///
        /// No hash, returns `X` component of shared point only.
        ///
        /// [ansix963]:  https://webstore.ansi.org/standards/ascx9/ansix9632011r2017
        case ansiX963
        
        /// Following no standard at all.
        ///
        /// No hash, returns the whole shared point.
        ///
        case noHashWholePoint
        
        func hashfp() -> (Optional<@convention(c) (Optional<UnsafeMutablePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafePointer<UInt8>>, Optional<UnsafeMutableRawPointer>) -> Int32>) {
            switch self {
            case .libsecp256kDefault: return secp256k1_ecdh_hash_function_default
            case .ansiX963: return ecdh_skip_hash_extract_only_x
            case .noHashWholePoint: return ecdh_skip_hash_extract_x_and_y
            }
        }
        
        var outputByteCount: Int {
            switch self {
            case .libsecp256kDefault: return Curve.Field.byteCount
            case .ansiX963: return Curve.Field.byteCount
            case .noHashWholePoint: return K1.Format.uncompressed.length
            }
        }
    }
}

// MARK: ECDH
extension FFI.ECDH {
    static func keyExchange(
        publicKey: FFI.PublicKey.Wrapped,
        privateKey: FFI.PrivateKey.Wrapped,
        serializeOutputFunction hashFp: SerializeFunction
    ) throws -> Data {
        
        var sharedPublicPointBytes = [UInt8](
            repeating: 0,
            count: hashFp.outputByteCount
        )
        var arbitraryData: [UInt8]? = {
            switch hashFp {
            case let .libsecp256kDefault(arbitraryData?): return [UInt8](arbitraryData)
            case .libsecp256kDefault(.none): return nil
            case .ansiX963, .noHashWholePoint: return nil
            }
        }()
        var publicKeyRaw = publicKey.raw
        try FFI.call(
            ifFailThrow: .failedToPerformDiffieHellmanKeyExchange
        ) { context in
            secp256k1_ecdh(
                context,
                &sharedPublicPointBytes, // output
                &publicKeyRaw, // pubkey
                privateKey.secureBytes.backing.bytes, // seckey
                hashFp.hashfp(), // hashfp
                &arbitraryData // arbitrary data pointer that is passed through to hashfp
            )
        }
        
        return Data(sharedPublicPointBytes)
        
    }
}


