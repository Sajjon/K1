import Foundation
import secp256k1

// MARK: - FFI.Group
extension FFI {
	enum Group {}
}

// MARK: - FFI.Group Operations
extension FFI.Group {
	/// Adds two points on the secp256k1 curve.
	/// - Parameters:
	///   - lhs: The first point
	///   - rhs: The second point
	/// - Returns: The sum of the two points
	/// - Throws: `K1.Error.underlyingLibsecp256k1` if the operation fails
	static func add(_ lhs: K1.Group.Point, _ rhs: K1.Group.Point) throws -> K1.Group.Point {
		return try FFI.toC { ffi in
			// Convert points to public keys
			let pk1 = try lhs.toPublicKey()
			let pk2 = try rhs.toPublicKey()
			
			// Use secp256k1_ec_pubkey_combine for addition
			var result = secp256k1_pubkey()
			
			return try withUnsafePointer(to: pk1.impl.wrapped.raw) { ptr1 in
				try withUnsafePointer(to: pk2.impl.wrapped.raw) { ptr2 in
					let pubkeyPointers: [UnsafePointer<secp256k1_pubkey>?] = [ptr1, ptr2]
					
					return try pubkeyPointers.withUnsafeBufferPointer { buffer in
						let success = secp256k1_ec_pubkey_combine(
							ffi.context,
							&result,
							buffer.baseAddress!,
							2
						)
						
						guard success == 1 else {
							throw K1.Error.underlyingLibsecp256k1Error(.groupOperation)
						}
						
						// Convert result back to point
						let resultWrapped = FFI.PublicKey.Wrapped(raw: result)
						let resultPublicKey = K1.KeyAgreement.PublicKey(impl: K1._PublicKeyImplementation(wrapped: resultWrapped))
						return try K1.Group.Point(publicKey: resultPublicKey)
					}
				}
			}
		}
	}
	
	/// Subtracts the second point from the first point on the secp256k1 curve.
	/// - Parameters:
	///   - lhs: The first point
	///   - rhs: The second point
	/// - Returns: The difference of the two points
	/// - Throws: `K1.Error.underlyingLibsecp256k1` if the operation fails
	static func subtract(_ lhs: K1.Group.Point, _ rhs: K1.Group.Point) throws -> K1.Group.Point {
		return try FFI.toC { ffi in
			// Convert points to public keys
			let pk1 = try lhs.toPublicKey()
			let pk2 = try rhs.toPublicKey()
			
			// Negate the second point in place
			var negatedPk2 = pk2.impl.wrapped.raw
			let negateSuccess = secp256k1_ec_pubkey_negate(ffi.context, &negatedPk2)
			
			guard negateSuccess == 1 else {
				throw K1.Error.underlyingLibsecp256k1Error(.groupOperation)
			}
			
			// Combine the first point with the negated second point
			var result = secp256k1_pubkey()
			
			return try withUnsafePointer(to: pk1.impl.wrapped.raw) { ptr1 in
				try withUnsafePointer(to: negatedPk2) { ptr2 in
					let pubkeyPointers: [UnsafePointer<secp256k1_pubkey>?] = [ptr1, ptr2]
					
					return try pubkeyPointers.withUnsafeBufferPointer { buffer in
						let combineSuccess = secp256k1_ec_pubkey_combine(
							ffi.context,
							&result,
							buffer.baseAddress!,
							2
						)
						
						guard combineSuccess == 1 else {
							throw K1.Error.underlyingLibsecp256k1Error(.groupOperation)
						}
						
						// Convert result back to point
						let resultWrapped = FFI.PublicKey.Wrapped(raw: result)
						let resultPublicKey = K1.KeyAgreement.PublicKey(impl: K1._PublicKeyImplementation(wrapped: resultWrapped))
						return try K1.Group.Point(publicKey: resultPublicKey)
					}
				}
			}
		}
	}
	
	/// Negates a point on the secp256k1 curve (multiplies by -1).
	/// - Parameter point: The point to negate
	/// - Returns: The negated point
	/// - Throws: `K1.Error.underlyingLibsecp256k1` if the operation fails
	static func negate(_ point: K1.Group.Point) throws -> K1.Group.Point {
		return try FFI.toC { ffi in
			// Convert point to public key
			let pk = try point.toPublicKey()
			
			// Use secp256k1_ec_pubkey_negate
			var negatedPk = pk.impl.wrapped.raw
			let success = secp256k1_ec_pubkey_negate(ffi.context, &negatedPk)
			
			guard success == 1 else {
				throw K1.Error.underlyingLibsecp256k1Error(.groupOperation)
			}
			
			// Convert result back to point
			let resultWrapped = FFI.PublicKey.Wrapped(raw: negatedPk)
			let resultPublicKey = K1.KeyAgreement.PublicKey(impl: K1._PublicKeyImplementation(wrapped: resultWrapped))
			return try K1.Group.Point(publicKey: resultPublicKey)
		}
	}
	
	/// Doubles a point on the secp256k1 curve (multiplies by 2).
	/// - Parameter point: The point to double
	/// - Returns: The doubled point
	/// - Throws: `K1.Error.underlyingLibsecp256k1` if the operation fails
	static func double(_ point: K1.Group.Point) throws -> K1.Group.Point {
		// Doubling is the same as adding a point to itself
		return try add(point, point)
	}
} 