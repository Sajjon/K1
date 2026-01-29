// MARK: - K1.ECDSA
extension K1 {
	/// A mechanism used to create or verify a cryptographic signature using
	/// the `secp256k1` elliptic curve digital signature algorithm (ECDSA),
	/// signatures that do not offer recovery of the public key.
	public enum ECDSA {}
}

// MARK: - K1.ECDSA.ValidationOptions
extension K1.ECDSA {
	/// Additional parameters used during validation of ECDSA signatures.
	public struct ValidationOptions {
		/// Whether or not to consider malleable signatures valid.
		public let malleabilityStrictness: MalleabilityStrictness

		public init(malleabilityStrictness: MalleabilityStrictness) {
			self.malleabilityStrictness = malleabilityStrictness
		}
	}
}

extension K1.ECDSA.ValidationOptions {
	/// The default behavior of ECDSA signature validation.
	public static let `default`: Self = .init(
		malleabilityStrictness: .rejected
	)

	// swiftlint:disable line_length

	/// Whether or not to consider malleable signatures valid.
	///
	/// [more]: https://github.com/bitcoin-core/secp256k1/blob/2e5e4b67dfb67950563c5f0ab2a62e25eb1f35c5/include/secp256k1.h#L510-L550
	public enum MalleabilityStrictness {
		/// Considers all malleable signatures **invalid**.
		case rejected

		/// Accepts malleable signatures valid.
		case accepted
	}

	// swiftlint:enable line_length
}

// MARK: - K1.ECDSA.SigningOptions
extension K1.ECDSA {
	/// Additional parameters used during signing, affects the signature produced.
	public struct SigningOptions: Sendable, Hashable {
		/// Behavior of nonce generation used durring signing.
		public let nonceFunction: NonceFunction

		public init(nonceFunction: NonceFunction) {
			self.nonceFunction = nonceFunction
		}
	}
}

extension K1.ECDSA.SigningOptions {
	/// The default behavior used during ECDSA signing.
	public static let `default`: Self = .init(nonceFunction: .deterministic())

	/// Behavior of nonce generation used durring signing.
	public enum NonceFunction: Sendable, Hashable {
		/// Use securely generate random data as nonce during ECDSA signing.
		case random

		/// Use deterministic nonces as per [`RFC6979`][rfc6979] during ECDSA signing.
		///
		/// [rfc6979]: https://www.rfc-editor.org/rfc/rfc6979
		case deterministic(arbitraryData: RFC6979ArbitraryData? = nil)
	}
}

// MARK: - K1.ECDSA.SigningOptions.NonceFunction.RFC6979ArbitraryData
extension K1.ECDSA.SigningOptions.NonceFunction {
	/// Optional arbitrary data passed during nonce generation using RFC6979.
	public struct RFC6979ArbitraryData: Sendable, Hashable {
		public let arbitraryData: [UInt8]
		public static let byteCount = Curve.Field.byteCount
		public init(arbitraryData: [UInt8]) throws {
			guard arbitraryData.count == Self.byteCount else {
				throw K1.Error.incorrectParameterSize
			}
			self.arbitraryData = arbitraryData
		}
	}
}
