//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2023-03-17.
//

import Foundation

extension Bridge {
    public enum Error: Sendable, Swift.Error, Hashable {
        case invalidPrivateKeyMustNotBeZero
        case invalidPrivateKeyMustBeSmallerThanOrder
        case failedToProduceSharedSecret
        case failedToComputePublicKeyFromPrivateKey
        case failedToPerformDiffieHellmanKeyExchange
        case failedToInitializePrivateKeyIncorrectByteCount(got: Int, expected: Int)
        case failedToCreateContextForSecp256k1
        case failedToDeserializePublicKey
        case failedToSerializePublicKey
        case failedToSchnorrVerifyGettingXFromPubKey
        case incorrectByteCountOfPublicKey(got: Int, acceptableLengths: [Int])
        case failedSignatureToConvertRecoverableSignatureToCompact
        case failedToConvertRecoverableSignatureToNonRecoverable
        case failedToRecoverPublicKey
        case unableToSignMessageHasInvalidLength(got: Int, expected: Int)
        case failedToInitializeKeyPairForSchnorrSigning
        case failedToSchnorrSignDigestProvidedRandomnessInvalidLength
        case failedToSchnorrSignDigest
        case failedToInitSchnorrSignatureInvalidByteCount(got: Int, expected: Int)
        case failedToSchnorrSignMessageInvalidLength
        case incorrectByteCountOfArbitraryDataForNonceFunction
        case failedToECDSASignDigest
        case unableToRecoverMessageHasInvalidLength(got: Int, expected: Int)
        case failedToComparePublicKeys
        case failedToSerializeDERSignature
        case failedToSerializeSignature
        case failedToParseRecoverableSignatireFromCompact
        case incorrectByteCountOfRawSignature
        case incorrectByteCountOfRawRecoverableSignature(got: Int, expected: Int)
        case failedToParseNonRecoverableSignatureFromCompactRepresentation
        case failedToDeserializeCompactRecoverableSignatureInvalidByteCount(got: Int, expected: Int)
        case failedToDeserializeCompactRSRecoverableSignatureInvalidByteCount(got: Int, expected: Int)
        case invalidRecoveryID(got: Int)
    }
}

extension Bridge.Error {
    
    public static func incorrectByteCountOfPublicKey(providedByteCount: Int) -> Self {
          .incorrectByteCountOfPublicKey(
            got: providedByteCount,
            acceptableLengths: Bridge.Format.allCases.map(\.length)
          )
      }
}
