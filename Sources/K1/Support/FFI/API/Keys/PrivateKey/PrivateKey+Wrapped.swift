import Foundation
import Secp256k1

// MARK: - FFI.PrivateKey
extension FFI {
	enum PrivateKey {
		// swiftlint:disable:next nesting
		struct Wrapped: @unchecked Sendable {
			let publicKey: FFI.PublicKey.Wrapped
			let secureBytes: SecureBytes

			fileprivate init(secureBytes: SecureBytes) throws {
				guard secureBytes.count == Curve.Field.byteCount else {
					throw K1.Error.incorrectKeySize
				}

				if secureBytes.allSatisfy({ $0 == .zero }) {
					throw K1.Error.invalidKey
				}

				self.secureBytes = secureBytes
				var secureBytes = secureBytes
				self.publicKey = try secureBytes.withUnsafeMutableBytes { seckey in
					var raw = PublicKeyRaw()

					try FFI.call(ifFailThrow: .publicKeyCreate) { context in
						secp256k1_ec_pubkey_create(
							context,
							&raw,
							seckey.baseAddress!
						)
					}

					return FFI.PublicKey.Wrapped(raw: raw)
				}
			}
		}
	}
}

// MARK: Init
extension FFI.PrivateKey.Wrapped {
	init(bytes: [UInt8]) throws {
		try self.init(secureBytes: .init(bytes: bytes))
	}

	init() {
		func generateNew() -> SecureBytes {
			var attempt = 0

			while attempt < 100 {
				defer { attempt += 1 }
				do {
					let secureBytes = SecureBytes(count: Curve.Field.byteCount)
					_ = try FFI.PrivateKey.Wrapped(secureBytes: secureBytes)
					return secureBytes
				} catch {
					// Failure (due to unlikely scenario that the private key scalar > order of the curve) => retry
				}
			}

			// Probability of this happening is:
			// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
			// (n / 2^256) ^ 100 = lim 0
			// I.e. will not happen.
			fatalError(
				"""
				Failed to generate private key after #\(attempt) attempts.
				You are the most unlucky person in the universe.
				Or by Occam's razor: the person writing this code made some error.
				"""
			)
		}
		// swiftlint:disable:next force_try
		try! self.init(secureBytes: generateNew())
	}
}

// MARK: Deserialize
extension FFI.PrivateKey {
	static func deserialize(
		rawRepresentation: some ContiguousBytes
	) throws -> Wrapped {
		try Wrapped(bytes: rawRepresentation.bytes)
	}
}
