import Foundation
import Secp256k1

// MARK: - FFI.Schnorr
extension FFI {
	enum Schnorr {}
}

// MARK: Schnorr Validate
extension FFI.Schnorr {
	static func isValid(
		signature: FFI.Schnorr.Wrapped,
		publicKey: FFI.PublicKey.Wrapped,
		message: Span<UInt8>
	) throws -> Bool {
		try FFI.toC { ffi -> Bool in
			var publicKeyX = secp256k1_xonly_pubkey()
			var publicKeyRaw = publicKey.raw
			try FFI.call(ifFailThrow: .xonlyPublicKeyFromPublicKey) { context in
				xOnlyPublicKeyFromPublicKey(
					context: context,
					outputXOnlyPublicKey: &publicKeyX,
					parity: nil,
					publicKey: &publicKeyRaw
				)
			}

			return ffi.validate { context in
				verifySchnorrSignature(
					context: context,
					signatureBytes: signature.bytes,
					msg: message,
					xOnlyPublicKey: &publicKeyX
				)
			}
		}
	}
}

// MARK: Schnorr Sign
extension FFI.Schnorr {
	static func sign(
		hashedMessage message: [UInt8],
		privateKey: FFI.PrivateKey.Wrapped,
		options: K1.Schnorr.SigningOptions = .default
	) throws -> FFI.Schnorr.Wrapped {
		guard
			message.count == Curve.Field.byteCount
		else {
			throw K1.Error.incorrectParameterSize
		}

		var signatureOut = [UInt8](repeating: 0, count: FFI.Schnorr.Wrapped.byteCount)

		var keyPair = secp256k1_keypair()

		try FFI.call(
			ifFailThrow: .keypairCreate
		) { context in
			secp256k1_keypair_create(
				context,
				&keyPair,
				privateKey.secureBytes.backing.bytes
			)
		}

		try FFI.call(
			ifFailThrow: .schnorrSign
		) { context in
			secp256k1_schnorrsig_sign32(
				context,
				&signatureOut,
				message,
				&keyPair,
				options.auxiliaryRandomData.bytes
			)
		}

		return try FFI.Schnorr.Wrapped(bytes: signatureOut)
	}
}
