import protocol CryptoKit.Digest
import struct CryptoKit.SHA256
import Foundation

// MARK: - K1.Schnorr
extension K1 {
	/// A mechanism used to create or verify a cryptographic signature using the `secp256k1` and Schnorr signature scheme.
	public enum Schnorr {
		// Just a namespace
	}
}

// MARK: - K1.Schnorr.SigningOptions
extension K1.Schnorr {
	public struct SigningOptions: Sendable, Hashable {
		public let auxiliaryRandomData: AuxiliaryRandomData?
		public init(auxiliaryRandomData: AuxiliaryRandomData? = nil) {
			self.auxiliaryRandomData = auxiliaryRandomData
		}
	}
}

extension K1.Schnorr.SigningOptions {
	public static let `default` = Self()

	public struct AuxiliaryRandomData: Sendable, Hashable {
		public let aux: [UInt8]

		public init(aux: some DataProtocol) throws {
			guard aux.count == Curve.Field.byteCount else {
				throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
			}
			self.aux = [UInt8](aux)
		}
	}
}
