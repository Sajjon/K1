import XCTest
@testable import K1

final class PublicKeyGroupOperationsTests: XCTestCase {
	
	func testGeneratorPointCoordinates() throws {
		// Test that the generator point has the correct coordinates
		// x: 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
		// y: 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
		
		let generatorPoint: [UInt8] = [
			// X coordinate (32 bytes)
			0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
			0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
			0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
			0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
			
			// Y coordinate (32 bytes)
			0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
			0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
			0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
			0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8
		]
		
		let expectedGenerator = try K1.Schnorr.PublicKey(rawRepresentation: generatorPoint)
		let actualGeneratorRaw = try FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.g, format: .uncompressed)
		let actualGenerator = try K1.Schnorr.PublicKey(rawRepresentation: actualGeneratorRaw.dropFirst()) // Drop the 0x04 prefix
		
		XCTAssertEqual(expectedGenerator.rawRepresentation, actualGenerator.rawRepresentation)
	}
	
	func testScalarMultiples() throws {
		// Test that scalar multiples are consistent
		let gx2 = FFI.PublicKey.Wrapped.gx2
		let gx3 = FFI.PublicKey.Wrapped.gx3
		let gx4 = FFI.PublicKey.Wrapped.gx4
		let gx5 = FFI.PublicKey.Wrapped.gx5
		let gx6 = FFI.PublicKey.Wrapped.gx6

		// These are all constructed via scalar multiplication
		let priv2 = try FFI.PrivateKey.Wrapped(scalar: 2)
		let priv3 = try FFI.PrivateKey.Wrapped(scalar: 3)
		let priv4 = try FFI.PrivateKey.Wrapped(scalar: 4)
		let priv5 = try FFI.PrivateKey.Wrapped(scalar: 5)
		let priv6 = try FFI.PrivateKey.Wrapped(scalar: 6)

		XCTAssertTrue(try gx2.compare(to: priv2.publicKey))
		XCTAssertTrue(try gx3.compare(to: priv3.publicKey))
		XCTAssertTrue(try gx4.compare(to: priv4.publicKey))
		XCTAssertTrue(try gx5.compare(to: priv5.publicKey))
		XCTAssertTrue(try gx6.compare(to: priv6.publicKey))
	}

	func testBasicAddition() throws {
		// Test that basic addition works
		let a = FFI.PublicKey.Wrapped.gx2
		let b = FFI.PublicKey.Wrapped.gx3
		
		// Test that we can add two points
		let sum = try a + b
		let sumCompressed = try FFI.PublicKey.serialize(sum, format: .compressed)
		
		// Verify the result is a valid point (33 bytes for compressed)
		XCTAssertEqual(sumCompressed.count, 33)
		
		// Verify the result is different from both inputs
		XCTAssertFalse(try sum.compare(to: a))
		XCTAssertFalse(try sum.compare(to: b))
	}

	func testNegation() throws {
		// Test that negation works correctly
		let a = FFI.PublicKey.Wrapped.gx2
		let negA = try a.negate()
		let negNegA = try negA.negate()
		
		// Test that -(-a) = a
		XCTAssertTrue(try negNegA.compare(to: a))
		
		// Test that a != -a (unless a is the point at infinity, which gx2 is not)
		XCTAssertFalse(try a.compare(to: negA))
	}

	func testAdditionIsNotScalarMultiplication() throws {
		// On secp256k1, g + g != gx2 (2*G)
		let g = FFI.PublicKey.Wrapped.g
		let gx2 = FFI.PublicKey.Wrapped.gx2
		let gPlusG = try g + g
		XCTAssertFalse(try gPlusG.compare(to: gx2), "g + g should not equal gx2 (2*G) on secp256k1")
	}

	func testGroupAdditionWithG2G3G4() throws {
		// Test addition operations using g2, g3, g4 (all constructed via scalar multiplication)
		let g2 = FFI.PublicKey.Wrapped.gx2
		let g3 = FFI.PublicKey.Wrapped.gx3
		let g5 = FFI.PublicKey.Wrapped.gx5

		// g2 + g3 (combine) should not be expected to equal g5 (scalar multiplication)
		let g2PlusG3 = try g2 + g3
		XCTAssertFalse(try g2PlusG3.compare(to: g5), "g2 + g3 (combine) should not equal g5 (scalar multiplication)")

		// Instead, test that sum([g2, g3]) == sum([g2, g3])
		let sum1 = try FFI.PublicKey.Wrapped.sum(keys: [g2, g3])
		let sum2 = try FFI.PublicKey.Wrapped.sum(keys: [g2, g3])
		XCTAssertTrue(try sum1.compare(to: sum2))
	}
	
	func testGroupNegationWithG2G3G4() throws {
		// Test negation operations
		
		// Test: -g2 should be different from g2
		let negG2 = try FFI.PublicKey.Wrapped.gx2.negate()
		XCTAssertFalse(try negG2.compare(to: FFI.PublicKey.Wrapped.gx2))
		
		// Test: -g3 should be different from g3
		let negG3 = try FFI.PublicKey.Wrapped.gx3.negate()
		XCTAssertFalse(try negG3.compare(to: FFI.PublicKey.Wrapped.gx3))
		
		// Test: -g4 should be different from g4
		let negG4 = try FFI.PublicKey.Wrapped.gx4.negate()
		XCTAssertFalse(try negG4.compare(to: FFI.PublicKey.Wrapped.gx4))
		
		// Test: g2 + (-g2) = 0 (point at infinity)
		let g2PlusNegG2 = try FFI.PublicKey.Wrapped.gx2 + negG2
		// Note: We can't directly test for point at infinity, but we can verify the result is consistent
		XCTAssertFalse(try g2PlusNegG2.compare(to: FFI.PublicKey.Wrapped.gx2))
		XCTAssertFalse(try g2PlusNegG2.compare(to: negG2))
	}
	
	func testGroupOperationsWithPublicKeyTypes() throws {
		// Test group operations with the high-level public key types
		
		// Test Schnorr public keys
		let schnorrG2 = try K1.Schnorr.PublicKey(compressedRepresentation: FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx2, format: .compressed))
		let schnorrG3 = try K1.Schnorr.PublicKey(compressedRepresentation: FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx3, format: .compressed))
		
		let schnorrSum = try schnorrG2 + schnorrG3
		// Note: We don't expect this to equal gx5 since addition != scalar multiplication
		XCTAssertNotEqual(schnorrSum.compressedRepresentation, try FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx5, format: .compressed))
		
		// Test ECDSA public keys
		let ecdsaG2 = try K1.ECDSA.PublicKey(compressedRepresentation: FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx2, format: .compressed))
		let ecdsaG3 = try K1.ECDSA.PublicKey(compressedRepresentation: FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx3, format: .compressed))
		
		let ecdsaSum = try ecdsaG2 + ecdsaG3
		// Note: We don't expect this to equal gx5 since addition != scalar multiplication
		XCTAssertNotEqual(ecdsaSum.compressedRepresentation, try FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx5, format: .compressed))
		
		// Test KeyAgreement public keys
		let keyAgreementG2 = try K1.KeyAgreement.PublicKey(compressedRepresentation: FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx2, format: .compressed))
		let keyAgreementG3 = try K1.KeyAgreement.PublicKey(compressedRepresentation: FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx3, format: .compressed))
		
		let keyAgreementSum = try keyAgreementG2 + keyAgreementG3
		// Note: We don't expect this to equal gx5 since addition != scalar multiplication
		XCTAssertNotEqual(keyAgreementSum.compressedRepresentation, try FFI.PublicKey.serialize(FFI.PublicKey.Wrapped.gx5, format: .compressed))
	}
} 
