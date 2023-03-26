import Foundation
import secp256k1

// MARK: - FFI.ECDSA
extension FFI {
	public enum ECDSA {}
}

extension FFI.ECDSA {
	public enum Recoverable {}
	public enum NonRecoverable {}
}

// MARK: - RawECDSASignature
protocol RawECDSASignature {
	init()
}

// MARK: - secp256k1_ecdsa_recoverable_signature + RawECDSASignature
extension secp256k1_ecdsa_recoverable_signature: RawECDSASignature {}

// MARK: - secp256k1_ecdsa_signature + RawECDSASignature
extension secp256k1_ecdsa_signature: RawECDSASignature {}

// MARK: - WrappedECDSASignature
protocol WrappedECDSASignature {
	associatedtype Raw: RawECDSASignature
	init(raw: Raw)
	var raw: Raw { get }
	static func sign() -> (OpaquePointer, UnsafeMutablePointer<Raw>, UnsafePointer<UInt8>, UnsafePointer<UInt8>, secp256k1_nonce_function?, UnsafeRawPointer?) -> Int32
}

// MARK: ECDSA Shared
extension FFI.ECDSA {
	internal static func _sign<WrappedSignature>(
		message: [UInt8],
		privateKey: FFI.PrivateKey.Wrapped,
		options: K1.ECDSA.SigningOptions = .default
	) throws -> WrappedSignature where WrappedSignature: WrappedECDSASignature {
		guard message.count == Curve.Field.byteCount else {
			throw K1.Error.incorrectParameterSize
		}

		var raw = WrappedSignature.Raw()

		try FFI.call(
			ifFailThrow: .ecdsaSign
		) { context in
			WrappedSignature.sign()(
				context,
				&raw,
				message,
				privateKey.secureBytes.backing.bytes,
				options.nonceFunction.function(),
				options.arbitraryData
			)
		}

		return .init(raw: raw)
	}
}

extension K1.ECDSA.SigningOptions {
	fileprivate var arbitraryData: [UInt8]? {
		switch self.nonceFunction {
		case .random: return nil
		case let .deterministic(arbitraryData): return arbitraryData?.arbitraryData
		}
	}
}

extension K1.ECDSA.SigningOptions.NonceFunction {
	fileprivate func function() -> Optional< @convention(c) (UnsafeMutablePointer<UInt8>?, UnsafePointer<UInt8>?, UnsafePointer<UInt8>?, UnsafePointer<UInt8>?, UnsafeMutableRawPointer?, UInt32) -> Int32> {
		switch self {
		case .deterministic:
			return secp256k1_nonce_function_rfc6979

		case .random:
			return { (
				nonce32: UnsafeMutablePointer<UInt8>?, // Out: pointer to a 32-byte array to be filled by the function.
				_: UnsafePointer<UInt8>?, // In: the 32-byte message hash being verified (will not be NULL)
				_: UnsafePointer<UInt8>?, // In: pointer to a 32-byte secret key (will not be NULL)
				_: UnsafePointer<UInt8>?, // In:  pointer to a 16-byte array describing the signature algorithm (will be NULL for ECDSA for compatibility).
				_: UnsafeMutableRawPointer?, // In: Arbitrary data pointer that is passed through.
				_: UInt32 // In: how many iterations we have tried to find a nonce. This will almost always be 0, but different attempt values are required to result in a different nonce.
			) -> Int32 /* Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail. */ in

				let count = Curve.Field.byteCount
				let secureBytes = SecureBytes(count: count)

				#if swift(>=5.8)
				nonce32?.update(from: secureBytes.bytes, count: count)
				#else
				secureBytes.withUnsafeBytes {
					nonce32?.assign(from: $0.baseAddress!.assumingMemoryBound(to: UInt8.self), count: count)
				}
				#endif

				// Returns: 1 if a nonce was successfully generated. 0 will cause signing to fail.
				return 1
			}
		}
	}
}
