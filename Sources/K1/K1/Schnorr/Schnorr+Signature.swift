import Foundation

// MARK: - K1.Schnorr.Signature
extension K1.Schnorr {
	/// A `secp256k1` elliptic curve signature using the [Schnorr signature scheme][scheme].
	///
	/// [scheme]: https://doi.org/10.1007%2F0-387-34805-0_22
	public struct Signature: Sendable, Hashable {
		typealias Wrapped = FFI.Schnorr.Wrapped
		internal let wrapped: Wrapped
		internal init(wrapped: Wrapped) {
			self.wrapped = wrapped
		}
	}
}

// MARK: Init
extension K1.Schnorr.Signature {
	public init(rawRepresentation: some DataProtocol) throws {
		try self.init(wrapped: .init(bytes: [UInt8](rawRepresentation)))
	}
}

// MARK: Serialize
extension K1.Schnorr.Signature {
	public var rawRepresentation: Data {
		wrapped.rawRepresentation
	}
}
