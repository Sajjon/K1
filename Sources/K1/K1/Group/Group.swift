import Foundation

// MARK: - K1.Group
extension K1 {
    /// A mechanism for performing low-level group operations on secp256k1 curve points.
    /// This includes point addition, subtraction, and negation operations.
    public enum Group {}
}

// MARK: - K1.Group.Point
extension K1.Group {
    /// A point on the secp256k1 curve in affine coordinates (x, y).
    /// This represents a point on the elliptic curve y² = x³ + 7.
    public struct Point: Sendable, Hashable {
        /// The x-coordinate of the point.
        public let x: Data
        /// The y-coordinate of the point.
        public let y: Data
        
        /// Creates a point from x and y coordinates.
        /// - Parameters:
        ///   - x: The x-coordinate as 32 bytes
        ///   - y: The y-coordinate as 32 bytes
        /// - Throws: `K1.Error.incorrectParameterSize` if coordinates are not 32 bytes
        public init(x: Data, y: Data) throws {
            guard x.count == Curve.Field.byteCount else {
                throw K1.Error.incorrectParameterSize
            }
            guard y.count == Curve.Field.byteCount else {
                throw K1.Error.incorrectParameterSize
            }
            self.x = x
            self.y = y
        }
        
        /// Creates a point from a public key.
        /// - Parameter publicKey: The public key to convert to a point
        /// - Throws: `K1.Error.publicKeySerialize` if the public key cannot be serialized
        public init(publicKey: K1.KeyAgreement.PublicKey) throws {
            let serialized = try FFI.PublicKey.serialize(publicKey.impl.wrapped, format: .uncompressed)
            // Remove the 0x04 prefix and split into x and y coordinates
            guard serialized.count == 65 && serialized[0] == 0x04 else {
                throw K1.Error.underlyingLibsecp256k1Error(.publicKeySerialize)
            }
            self.x = serialized[1..<33]
            self.y = serialized[33..<65]
        }
        
        /// Converts this point to a public key.
        /// - Returns: A public key representing this point
        /// - Throws: `K1.Error.publicKeyParse` if the point cannot be converted to a public key
        public func toPublicKey() throws -> K1.KeyAgreement.PublicKey {
            let serialized = Data([0x04]) + x + y
            let wrapped = try FFI.PublicKey.deserialize(x963Representation: serialized)
            return K1.KeyAgreement.PublicKey(impl: K1._PublicKeyImplementation(wrapped: wrapped))
        }
        
        /// The point at infinity (neutral element for group operations).
        public static let infinity: Point = {
            // Safe to use try! here since we know the data is valid
            try! Point(x: Data(repeating: 0, count: 32), y: Data(repeating: 0, count: 32))
        }()
        
        /// Checks if this point is the point at infinity.
        public var isInfinity: Bool {
            return x == Data(repeating: 0, count: 32) && y == Data(repeating: 0, count: 32)
        }
    }
}

// MARK: - K1.Group.Operations
extension K1.Group {
    /// Adds two points on the secp256k1 curve.
    /// - Parameters:
    ///   - lhs: The first point
    ///   - rhs: The second point
    /// - Returns: The sum of the two points
    /// - Throws: `K1.Error.groupOperation` if the operation fails
    public static func add(_ lhs: Point, _ rhs: Point) throws -> Point {
        return try FFI.Group.add(lhs, rhs)
    }
    
    /// Subtracts the second point from the first point on the secp256k1 curve.
    /// - Parameters:
    ///   - lhs: The first point
    ///   - rhs: The second point
    /// - Returns: The difference of the two points
    /// - Throws: `K1.Error.groupOperation` if the operation fails
    public static func subtract(_ lhs: Point, _ rhs: Point) throws -> Point {
        return try FFI.Group.subtract(lhs, rhs)
    }
    
    /// Negates a point on the secp256k1 curve (multiplies by -1).
    /// - Parameter point: The point to negate
    /// - Returns: The negated point
    /// - Throws: `K1.Error.groupOperation` if the operation fails
    public static func negate(_ point: Point) throws -> Point {
        return try FFI.Group.negate(point)
    }
    
    /// Doubles a point on the secp256k1 curve (multiplies by 2).
    /// - Parameter point: The point to double
    /// - Returns: The doubled point
    /// - Throws: `K1.Error.groupOperation` if the operation fails
    public static func double(_ point: Point) throws -> Point {
        return try FFI.Group.double(point)
    }
}

// MARK: - K1.Group.Point Operators
extension K1.Group.Point {
    /// Adds two points using the `+` operator.
    public static func + (lhs: Self, rhs: Self) throws -> Self {
        return try K1.Group.add(lhs, rhs)
    }
    
    /// Subtracts the second point from the first using the `-` operator.
    public static func - (lhs: Self, rhs: Self) throws -> Self {
        return try K1.Group.subtract(lhs, rhs)
    }
    
    /// Negates a point using the unary `-` operator.
    public static prefix func - (point: Self) throws -> Self {
        return try K1.Group.negate(point)
    }
}