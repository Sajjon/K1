import XCTest
@testable import K1

final class GroupTests: XCTestCase {
	
	func testPointCreation() throws {
		// Create a valid point from a public key
		let privateKey = K1.KeyAgreement.PrivateKey()
		let publicKey = privateKey.publicKey
		let point = try K1.Group.Point(publicKey: publicKey)
		
		XCTAssertEqual(point.x.count, 32)
		XCTAssertEqual(point.y.count, 32)
		XCTAssertFalse(point.isInfinity)
	}
	
	func testPointFromPublicKey() throws {
		// Create a private key and get its public key
		let privateKey = K1.KeyAgreement.PrivateKey()
		let publicKey = privateKey.publicKey
		
		// Convert public key to point
		let point = try K1.Group.Point(publicKey: publicKey)
		
		// Convert back to public key
		let convertedPublicKey = try point.toPublicKey()
		
		// They should be equal
		XCTAssertEqual(publicKey.rawRepresentation, convertedPublicKey.rawRepresentation)
	}
	
	func testPointNegation() throws {
		// Create a valid point from a public key
		let privateKey = K1.KeyAgreement.PrivateKey()
		let publicKey = privateKey.publicKey
		let point = try K1.Group.Point(publicKey: publicKey)
		
		// Negate the point
		let negatedPoint = try K1.Group.negate(point)
		
		// X coordinate should remain the same
		XCTAssertEqual(negatedPoint.x, point.x)
		
		// Y coordinate should be different (negated)
		XCTAssertNotEqual(negatedPoint.y, point.y)
		
		// Negating twice should give the original point
		let doubleNegated = try K1.Group.negate(negatedPoint)
		XCTAssertEqual(doubleNegated.x, point.x)
		XCTAssertEqual(doubleNegated.y, point.y)
	}
	
	func testInfinityPoint() {
		let infinity = K1.Group.Point.infinity
		XCTAssertTrue(infinity.isInfinity)
		XCTAssertEqual(infinity.x, Data(repeating: 0, count: 32))
		XCTAssertEqual(infinity.y, Data(repeating: 0, count: 32))
	}
	
	func testPointOperators() throws {
		// Create valid points from public keys
		let privateKey1 = K1.KeyAgreement.PrivateKey()
		let publicKey1 = privateKey1.publicKey
		let point1 = try K1.Group.Point(publicKey: publicKey1)
		
		let privateKey2 = K1.KeyAgreement.PrivateKey()
		let publicKey2 = privateKey2.publicKey
		let point2 = try K1.Group.Point(publicKey: publicKey2)
		
		// Test negation operator
		let negated = try -point1
		XCTAssertEqual(negated.x, point1.x)
		XCTAssertNotEqual(negated.y, point1.y)
		
		// Test addition and subtraction
		let sum = try point1 + point2
		XCTAssertEqual(sum.x.count, 32)
		XCTAssertEqual(sum.y.count, 32)
		
		let difference = try point1 - point2
		XCTAssertEqual(difference.x.count, 32)
		XCTAssertEqual(difference.y.count, 32)
	}
	
	func testPointAddition() throws {
		// Create two valid points
		let privateKey1 = K1.KeyAgreement.PrivateKey()
		let point1 = try K1.Group.Point(publicKey: privateKey1.publicKey)
		
		let privateKey2 = K1.KeyAgreement.PrivateKey()
		let point2 = try K1.Group.Point(publicKey: privateKey2.publicKey)
		
		// Test addition
		let sum = try K1.Group.add(point1, point2)
		XCTAssertEqual(sum.x.count, 32)
		XCTAssertEqual(sum.y.count, 32)
		
		// Test that addition is commutative
		let sum2 = try K1.Group.add(point2, point1)
		XCTAssertEqual(sum.x, sum2.x)
		XCTAssertEqual(sum.y, sum2.y)
	}
	
	func testPointSubtraction() throws {
		// Create two valid points
		let privateKey1 = K1.KeyAgreement.PrivateKey()
		let point1 = try K1.Group.Point(publicKey: privateKey1.publicKey)
		
		let privateKey2 = K1.KeyAgreement.PrivateKey()
		let point2 = try K1.Group.Point(publicKey: privateKey2.publicKey)
		
		// Test subtraction
		let difference = try K1.Group.subtract(point1, point2)
		XCTAssertEqual(difference.x.count, 32)
		XCTAssertEqual(difference.y.count, 32)
		
		// Test that (a - b) + b = a
		let reconstructed = try K1.Group.add(difference, point2)
		XCTAssertEqual(reconstructed.x, point1.x)
		XCTAssertEqual(reconstructed.y, point1.y)
	}
	
	func testPointDoubling() throws {
		// Create a valid point
		let privateKey = K1.KeyAgreement.PrivateKey()
		let point = try K1.Group.Point(publicKey: privateKey.publicKey)
		
		// Test doubling
		let doubled = try K1.Group.double(point)
		XCTAssertEqual(doubled.x.count, 32)
		XCTAssertEqual(doubled.y.count, 32)
		
		// Test that doubling is the same as adding to itself
		let selfSum = try K1.Group.add(point, point)
		XCTAssertEqual(doubled.x, selfSum.x)
		XCTAssertEqual(doubled.y, selfSum.y)
	}
	
	func testInvalidPointCreation() {
		// Test with wrong size coordinates
		let invalidX = Data(repeating: 1, count: 16) // Too short
		let validY = Data(repeating: 2, count: 32)
		
		XCTAssertThrowsError(try K1.Group.Point(x: invalidX, y: validY))
		XCTAssertThrowsError(try K1.Group.Point(x: validY, y: invalidX))
	}
} 