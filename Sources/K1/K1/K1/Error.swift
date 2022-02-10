//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


public extension K1 {
    
    enum Error: Swift.Error, Equatable {
        
        /// The private key scalar was either 0 or larger then the order of the
        /// curve.
        case invalidPrivateKeyMustNotBeZero
        case invalidPrivateKeyMustBeSmallerThan(order: Data)

        case incorrectByteCountOfPrivateKey(got: Int, expected: Int)
        
        case incorrectByteCountOfRawSignature
        
        case failedToCreateContextForSecp256k1
        case failedToUpdateContextRandomization
        case failedToComputePublicKeyFromPrivateKey
        case incorrectByteCountOfMessageToValidate
        case failedToCompressPublicKey
        case failedToUncompressPublicKey
        
        case incorrectByteCountOfPublicKey(got: Int, acceptableLengths: [Int])
        case failedToParsePublicKeyFromBytes
        case failedToParseDERSignature
        case failedToSerializeCompactSignature
        case failedToSerializeDERSignature
        case failedToECDSASignDigest
        case failedToNormalizeECDSASignature
        case failedToSchnorrSignMessageInvalidLength
        case failedToInitializeKeyPairForSchnorrSigning
        case failedToSchnorrSignDigest
        case failedToSchnorrSignDigestProvidedRandomnessInvalidLength
        case failedToSchnorrSignErrorGettingPubKeyFromKeyPair
        case failedToSchnorrVerifyGettingXFromPubKey
        case failedToSchnorrSignDigestDidNotPassVerification
        case failedToPerformDiffieHellmanKeyExchange
        case incorrectByteCountOfAuxilaryDataForSchnorr
        case incorrectByteCountOfMessageToECDSASign
        case incorrectByteCountOfArbitraryDataForNonceFunction
        case failedToSerializePublicKeyIntoBytes
        case failedToRecognizeSignatureType(onlySupportedSchemesAre: [SigningScheme])
    }

}

extension K1.Error {
    static func invalidSizeOfPrivateKey(providedByteCount: Int) -> Self {
        .incorrectByteCountOfPrivateKey(got: providedByteCount, expected: K1.Curve.Field.byteCount)
    }
    static let invalidPrivateKeyMustBeSmallerThanCurveOrder: Self =
        .invalidPrivateKeyMustBeSmallerThan(order: K1.Curve.order.serialize())
    
    static func incorrectByteCountOfPublicKey(providedByteCount: Int) -> Self {
        .incorrectByteCountOfPublicKey(got: providedByteCount, acceptableLengths: K1.Format.allCases.map(\.length))
    }
}
