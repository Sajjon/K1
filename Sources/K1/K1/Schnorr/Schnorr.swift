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
	/// Additional parameters used during signing, affects the signature produced.
	public struct SigningOptions: Sendable, Hashable {
		/// Behavior of auxiliary random data, either none, secure random or 32 specific bytes.
		public let auxiliaryRandomData: AuxiliaryRandomData

		public init(auxiliaryRandomData: AuxiliaryRandomData = .default) {
			self.auxiliaryRandomData = auxiliaryRandomData
		}
	}
}

extension K1.Schnorr.SigningOptions {
	public static let `default` = Self()

	/// Behavior of auxiliary random data, either none, secure random or 32 specific bytes.
	public enum AuxiliaryRandomData: Sendable, Hashable {
		/// Use no auxiliary random data at all.
		case none

		/// Use the 32 specified bytes as auxiliary data.
		case specific(Aux32)

		/// Securely generate 32 random bytes.
		case random
	}
}

extension K1.Schnorr.SigningOptions.AuxiliaryRandomData {
	var bytes: [UInt8]? {
		switch self {
		case .none: return nil
		case .random: return SecureBytes(count: Aux32.byteCount).bytes
		case let .specific(aux): return aux.aux
		}
	}

	/// The default behavior of auxiliary random data.
	public static let `default` = Self.random

	/// 32 bytes of fresh randomness. While recommended to provide this, it is only supplemental to security and can be nil.
	/// By default we generate secure random bytes.
	public struct Aux32: Sendable, Hashable {
		public let aux: [UInt8]
		public static let byteCount = Curve.Field.byteCount
		public init(aux: some DataProtocol) throws {
			guard aux.count == Self.byteCount else {
				throw K1.Error.failedToSchnorrSignDigestProvidedRandomnessInvalidLength
			}
			self.aux = [UInt8](aux)
		}
	}
}
