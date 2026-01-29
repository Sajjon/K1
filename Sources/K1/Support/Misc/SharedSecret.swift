import Foundation

// MUST match https://github.com/apple/swift-crypto/blob/main/Sources/Crypto/Key%20Agreement/DH.swift#L34
import struct CryptoKit.SharedSecret

// MARK: - __SharedSecret
/// A Key Agreement Result
/// A SharedSecret has to go through a Key Derivation Function before being able to use by a symmetric key operation.
struct __SharedSecret { // swiftlint:disable:this type_name
	var ss: SecureBytes // swiftlint:disable:this identifier_name
}

extension CryptoKit.SharedSecret {
	init(data: Data) throws {
		// swiftlint:disable:next identifier_name
		let __sharedSecret = __SharedSecret(ss: .init(bytes: data))
		let sharedSecret = unsafeBitCast(__sharedSecret, to: SharedSecret.self)
		guard sharedSecret.withUnsafeBytes({ Data($0).count == data.count }) else {
			throw K1.Error.internalFailure(.sharedSecretIncorrectSize)
		}

		self = sharedSecret
	}
}
