import Testing
import Secp256k1
import Foundation
import K1Macros

struct Safe {}
extension Safe {
	#makeSafe("cloneSpanOfLength3", cloneSpanOfLength3Unsafe, 3)
}


@Suite("Apinotes Tests")
struct Test {
	@available(macOS 26.0, *)
	@Test
	func `C get Swiftified by apinotes file with non-nullability and MutableSpan`() {

		expectAllEqual(to: 5) { (bytes: inout InlineArray<3, UInt8>) in
			var span = bytes.mutableSpan
			fillWithFives(span: &span)
		}
	}

	@available(macOS 26.0, *)
	@Test
	func `C fixed length`() {
		let source: InlineArray<3, UInt8> = [7, 7, 7]
		var destination: InlineArray<3, UInt8> = [0, 0, 0]

		Safe().cloneSpanOfLength3(
			into: &destination,
			from: source
		)

		for index in 0..<destination.count {
			#expect(destination[index] == 7)
		}
	}
}


@available(macOS 26.0, *)
func allEqual<let C: Int, Element: Equatable>(
	to expectedElement: Element,
	defaultElement: Element,
	initBytes: (inout InlineArray<C, Element>) -> Void
) -> Bool {
	var bytes: InlineArray<C, Element> = .init(repeating: defaultElement)
	initBytes(&bytes)
	for index in 0..<bytes.count {
		guard bytes[index] == expectedElement else {
			return false
		}
	}
	return true
}

@available(macOS 26.0, *)
func expectAllEqual<let C: Int, Element: AdditiveArithmetic>(
	to expectedElement: Element,
	initBytes: @escaping (inout InlineArray<C, Element>) -> Void,
	file: StaticString = #filePath,
	line: UInt = #line
) {
	#expect(
		allEqual(
			to: expectedElement,
			defaultElement: .zero,
			initBytes: initBytes
		),
		"in file: \(file), line: \(line)"
	)
}
