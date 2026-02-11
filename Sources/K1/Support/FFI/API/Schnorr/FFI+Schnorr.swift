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
	) -> Bool {
		FFI.toC { ffi -> Bool in
			var publicKeyX = PublicKeyXOnlyRaw()
			var publicKeyRaw = publicKey.raw
			ffi.call { context in
				_ = xOnlyPublicKeyFromPublicKey(
					context: context,
					outputXOnlyPublicKey: &publicKeyX,
					parity: nil,
					publicKey: &publicKeyRaw
				)
			}

			return ffi.call { context in
				verifySchnorrSignature(
					context: context,
					signatureBytes: signature.bytes,
					msg: message,
					xOnlyPublicKey: &publicKeyX
				)
			} == .success
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

		var keyPair = KeypairRaw()

		try FFI.call(
			ifFailThrow: .keypairCreate
		) { context in
			keypairFromPrivateKey(
				context: context,
				outputKeyPair: &keyPair,
				privateKeyBytes: privateKey.secureBytes.backing.bytes
			)
		}

		try FFI.call(
			ifFailThrow: .schnorrSign
		) { context in
			schnorrSign(
				context: context,
				outputSignatureBytes: &signatureOut,
				message: message,
				keypair: &keyPair,
				auxiliaryRandomData: options.auxiliaryRandomData.bytes
			)
		}

		return try FFI.Schnorr.Wrapped(bytes: signatureOut)
	}
}
