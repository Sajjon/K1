import Foundation

// FIXME: These are temporary, and should be removed. We should upgrade whole code base to use Span/InlineArray as much as possible.

// MARK: - Shared helpers
@usableFromInline
func withSpanFromArray<R>(
	_ bytes: [UInt8],
	_ body: (Span<UInt8>) throws -> R
) rethrows -> R {
	try bytes.withUnsafeBufferPointer { buf in
		try body(Span(_unsafeElements: buf))
	}
}

@usableFromInline
func withSpanFromData<R>(
	_ data: some DataProtocol,
	_ body: (Span<UInt8>) throws -> R
) rethrows -> R {
	if let contiguous = data as? any ContiguousBytes {
		return try contiguous.withUnsafeBytes { raw in
			let buf = raw.bindMemory(to: UInt8.self)
			return try body(Span(_unsafeElements: buf))
		}
	}

	var copy = [UInt8](data)
	return try copy.withUnsafeMutableBufferPointer { buf in
		let readonly = UnsafeBufferPointer(buf)
		return try body(Span(_unsafeElements: readonly))
	}
}

@usableFromInline
func withSpanFromContiguousBytes<C: ContiguousBytes, R>(
	_ bytes: C,
	_ body: (Span<UInt8>) throws -> R
) rethrows -> R {
	try bytes.withUnsafeBytes { raw in
		let buf = raw.bindMemory(to: UInt8.self)
		return try body(Span(_unsafeElements: buf))
	}
}
