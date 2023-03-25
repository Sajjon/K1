import Foundation

extension ContiguousBytes {
	@inlinable
	var bytes: [UInt8] {
		withUnsafeBytes { pointer in
			Array(pointer)
		}
	}
}
