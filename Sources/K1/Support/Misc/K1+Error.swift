import Foundation

// MARK: - K1.Error
extension K1 {
	/// General cryptography errors used by K1.
	public enum Error: Sendable, Swift.Error, Hashable {
		/// The key is invalid.
		case invalidKey

		/// The key size is incorrect.
		case incorrectKeySize

		/// The parameter is invalid.
		case invalidParameter

		/// The parameter size is incorrect.
		case incorrectParameterSize

		/// The underlying `libsecp256k1` library is unable to complete the requested action.
		case underlyingLibsecp256k1(error: Int)

		/// This library is unable to complete the requested action.
		case internalFailure(error: UInt)
	}
}

extension K1.Error {
	static func underlyingLibsecp256k1Error(_ error: FFI.Error) -> Self {
		.underlyingLibsecp256k1(error: error.rawValue)
	}

	static func internalFailure(_ error: InternalFailure) -> Self {
		.internalFailure(error: error.rawValue)
	}
}

// MARK: - InternalFailure
enum InternalFailure: UInt, Sendable, Swift.Error, Hashable {
	/// Failed to cast to `CryptoKit.SharedSecret` from representation.
	case sharedSecretIncorrectSize
}

// MARK: - FFI.Error
extension FFI {
	enum Error: Int, Sendable, Swift.Error, Hashable {
		case failedToCreateContextForSecp256k1

		//// `secp256k1_ecdsa_signature_parse_compact` failed
		case ecdsaSignatureParseCompact

		/// `secp256k1_ecdsa_signature_parse_der` failed
		case ecdsaSignatureParseDER

		/// `secp256k1_ecdsa_signature_serialize_compact` failed
		case ecdsaSignatureSerializeCompact

		/// `secp256k1_ecdsa_signature_serialize_der` failed
		case ecdsaSignatureSerializeDER

		/// `secp256k1_ecdsa_recoverable_signature_parse_compact` failed
		case recoverableSignatureParseCompact

		/// `secp256k1_ecdsa_recoverable_signature_serialize_compact` failed
		case recoverableSignatureSerializeCompact

		/// `secp256k1_ecdsa_recoverable_signature_convert` failed
		case recoverableSignatureConvert

		/// `secp256k1_ecdsa_recover` failed
		case recover

		/// `secp256k1_ec_pubkey_parse` failed
		case publicKeyParse

		/// `secp256k1_ec_pubkey_serialize` failed
		case publicKeySerialize

		/// `secp256k1_ecdh` failed
		case ecdh

		/// `secp256k1_ecdsa_sign_recoverable` or `secp256k1_ecdsa_sign` failed
		case ecdsaSign

		/// `secp256k1_xonly_pubkey_from_pubkey` failed
		case xonlyPublicKeyFromPublicKey

		/// `secp256k1_keypair_create` failed
		case keypairCreate

		/// `secp256k1_schnorrsig_sign32` failed
		case schnorrSign

		/// `secp256k1_ec_pubkey_create`
		case publicKeyCreate

		/// Group operation (point addition, subtraction, etc.) failed
		case groupOperation
	}
}

// MARK: - K1.Error + CustomDebugStringConvertible
extension K1.Error: CustomDebugStringConvertible {
	public var debugDescription: String {
		switch self {
		case .incorrectKeySize:
			return "incorrect key size"
		case .incorrectParameterSize:
			return "incorrect parameter size"
		case .invalidParameter:
			return "invalid parameter"
		case .invalidKey: return "invalidKey"
		case let .internalFailure(rawValue):
			guard let internalFailure = InternalFailure(rawValue: rawValue) else {
				return "failure"
			}
			let reason: String = {
				switch internalFailure {
				case .sharedSecretIncorrectSize:
					return "Failed to form SharedSecret"
				}
			}()
			return "failure reason: \(reason)"
		case let .underlyingLibsecp256k1(rawValue):
			guard let ffi = FFI.Error(rawValue: rawValue) else {
				return "Underlying libsecp256k1 failure."
			}
			let call: String = {
				switch ffi {
				case .ecdh: return "ecdh"
				case .ecdsaSign: return "ECDSA sign"
				case .ecdsaSignatureParseCompact: return "ECDSA signature parse compact"
				case .failedToCreateContextForSecp256k1:
					return "create context"
				case .ecdsaSignatureParseDER:
					return "ECDSA signature parse DER"
				case .ecdsaSignatureSerializeCompact:
					return "ECDSA signature serialize compact"
				case .ecdsaSignatureSerializeDER:
					return "ECDSA signature serialize DER"
				case .recoverableSignatureParseCompact:
					return "Recoverable ECDSA signature parse compact"
				case .recoverableSignatureSerializeCompact:
					return "Recoverable ECDSA signature serialize compact"
				case .recoverableSignatureConvert:
					return "Recoverable ECDSA convert to non-recoverable"
				case .recover:
					return "Recover PublicKey"
				case .publicKeyParse:
					return "PublicKey parse"
				case .publicKeySerialize:
					return "PublicKey serialize"
				case .xonlyPublicKeyFromPublicKey:
					return "Parse PublicKey from Xonly PublicKey"
				case .keypairCreate:
					return "Keypair create"
				case .schnorrSign:
					return "Schnorr sign"
				case .publicKeyCreate:
					return "PublicKey create"
				case .groupOperation:
					return "Group operation"
				}
			}()
			return "libsecp256k \(call) failed."
		}
	}
}
