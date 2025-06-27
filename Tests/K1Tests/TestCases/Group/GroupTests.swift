import XCTest
@testable import K1

final class GroupTests: XCTestCase {
	
	func testPointCreation() throws {
		// Test creating a point from coordinates
		let x = Data(repeating: 1, count: 32)
		let y = Data(repeating: 2, count: 32)
		let point = try K1.Group.Point(x: x, y: y)
		
		XCTAssertEqual(point.x, x)
		XCTAssertEqual(point.y, y)
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
		// Create a point
		let x = Data(repeating: 1, count: 32)
		let y = Data(repeating: 2, count: 32)
		let point = try K1.Group.Point(x: x, y: y)
		
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
		// Test the operator syntax
		let x1 = Data(repeating: 1, count: 32)
		let y1 = Data(repeating: 2, count: 32)
		let point1 = try K1.Group.Point(x: x1, y: y1)
		
		let x2 = Data(repeating: 3, count: 32)
		let y2 = Data(repeating: 4, count: 32)
		let point2 = try K1.Group.Point(x: x2, y: y2)
		
		// Test negation operator
		let negated = try -point1
		XCTAssertEqual(negated.x, point1.x)
		XCTAssertNotEqual(negated.y, point1.y)
		
		// Note: Addition and subtraction will throw groupOperation error
		// since the low-level implementation is not yet complete
		XCTAssertThrowsError(try point1 + point2)
		XCTAssertThrowsError(try point1 - point2)
	}
	
	func testInvalidPointCreation() {
		// Test with wrong size coordinates
		let invalidX = Data(repeating: 1, count: 16) // Too short
		let validY = Data(repeating: 2, count: 32)
		
		XCTAssertThrowsError(try K1.Group.Point(x: invalidX, y: validY))
		XCTAssertThrowsError(try K1.Group.Point(x: validY, y: invalidX))
	}
} 