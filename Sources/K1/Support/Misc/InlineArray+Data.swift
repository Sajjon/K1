import Foundation

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
extension InlineArray where Element == UInt8 {
	init(hex: String) throws {
		let data = try Data(hex: hex)
		try self.init(data: data)
	}

	init(data: Data) throws {
		guard data.count == count else {
			throw InlineArrayError.wrongLength(expected: count, got: data.count)
		}
		self = .init(repeating: 0)
		data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
			for index in 0 ..< count {
				self[index] = raw[index]
			}
		}
	}
}

@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
enum InlineArrayError: Error {
	case wrongLength(expected: Int, got: Int)
}
