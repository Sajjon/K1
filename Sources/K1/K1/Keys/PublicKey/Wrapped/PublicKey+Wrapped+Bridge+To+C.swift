//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


import secp256k1

extension Bridge {
    
    static func publicKeyParse(
        raw: [UInt8]
    ) throws -> Data {
        
        guard K1.Format.allCases.map(\.length).contains(raw.count) else {
            throw K1.Error.incorrectByteCountOfPublicKey(providedByteCount: raw.count)
        }
        
        var publicKeyBytesMaybeCompressed = raw
        var publicKeyBridgedToC = secp256k1_pubkey()
        
        try Self.call(
            ifFailThrow: .failedToParsePublicKeyFromBytes
        ) { context in
            /* Parse a variable-length public key into the pubkey object. */
            secp256k1_ec_pubkey_parse(
                context,
                &publicKeyBridgedToC,
                &publicKeyBytesMaybeCompressed,
                raw.count
            )
        }

        if publicKeyBytesMaybeCompressed.count == K1.Format.uncompressed.length {
            return Data(publicKeyBytesMaybeCompressed)
        }
        
        // Was compressed, need to uncompress
        
        var publicKeyBytesUncompressedLength = K1.Format.uncompressed.length
        var publicKeyBytesUncompressed = [UInt8].init(repeating: 0, count: publicKeyBytesUncompressedLength)
        
        try Self.call(
            ifFailThrow: .failedToUncompressPublicKey
        ) { context in
            /* "Serialize a pubkey object into a serialized byte sequence." */
            secp256k1_ec_pubkey_serialize(
                context,
                &publicKeyBytesUncompressed,
                &publicKeyBytesUncompressedLength,
                &publicKeyBridgedToC,
                K1.Format.uncompressed.rawValue
            )
        }
        
        return Data(publicKeyBytesUncompressed)
        
    }
    
    static func compress(
        publicKey: K1.PublicKey.Wrapped
    ) throws -> Data {
        
        var publicKeyBridgedToC = secp256k1_pubkey()

        try Self.call(ifFailThrow: .failedToParsePublicKeyFromBytes) { context in
            /* Parse a variable-length public key into the pubkey object. */
            secp256k1_ec_pubkey_parse(
                context,
                &publicKeyBridgedToC,
                publicKey.uncompressedRaw,
                publicKey.uncompressedRaw.count
            )
        }
 
        let publicKeyFormat = K1.Format.compressed
        
        var publicKeyCompressedByteCount = publicKeyFormat.length
        var publicKeyBytes = [UInt8](
            repeating: 0,
            count: publicKeyCompressedByteCount
        )
        
        try Self.call(
            ifFailThrow: .failedToCompressPublicKey
        ) { context in
            /* "Serialize a pubkey object into a serialized byte sequence." */
            secp256k1_ec_pubkey_serialize(
                context,
                &publicKeyBytes,
                &publicKeyCompressedByteCount,
                &publicKeyBridgedToC,
                publicKeyFormat.rawValue
            )
        }
        
        return Data(publicKeyBytes)
    }
    
    
    static func publicKeyCreate(privateKeyBytes: [UInt8]) throws -> Data {
        
        guard
            privateKeyBytes.count == K1.PrivateKey.Wrapped.byteCount
        else {
            throw K1.Error.invalidSizeOfPrivateKey(providedByteCount: privateKeyBytes.count)
        }
        
        let publicKeyFormat = K1.Format.uncompressed
        var publicKeyByteCount = publicKeyFormat.length
        var publicKeyBridgedToC = secp256k1_pubkey()
        
        var publicKeyBytes = [UInt8](
            repeating: 0,
            count: publicKeyFormat.length
        )
        
        try Bridge.toC { bridge in
            
            try bridge.call(
                ifFailThrow: .failedToUpdateContextRandomization
            ) {
                secp256k1_context_randomize($0, privateKeyBytes)
            }
            
            try bridge.call(
                ifFailThrow: .failedToComputePublicKeyFromPrivateKey
            ) {
                /* "Compute the public key for a secret key." */
                secp256k1_ec_pubkey_create($0, &publicKeyBridgedToC, privateKeyBytes)
            }
            
            try bridge.call(
                ifFailThrow: .failedToSerializePublicKeyIntoBytes
            ) {
                /* "Serialize a pubkey object into a serialized byte sequence." */
                secp256k1_ec_pubkey_serialize(
                    $0,
                    &publicKeyBytes,
                    &publicKeyByteCount,
                    &publicKeyBridgedToC,
                    publicKeyFormat.rawValue
                )
            }
        }
        
        assert(publicKeyByteCount == publicKeyFormat.length)
        
        return Data(publicKeyBytes)
    }
}


internal extension K1.PublicKey.Wrapped {
    
    static func `import`(from raw: [UInt8]) throws -> Self {
        let publicKeyBytes = try Bridge.publicKeyParse(raw: raw)
        return try Self(uncompressedRaw: publicKeyBytes.bytes)
    }
    
    static func derive(
        privateKeyBytes: [UInt8]
    ) throws -> Self {
        let publicKeyRaw = try Bridge.publicKeyCreate(privateKeyBytes: privateKeyBytes)
        return try Self(uncompressedRaw: publicKeyRaw.bytes)
    }

}
