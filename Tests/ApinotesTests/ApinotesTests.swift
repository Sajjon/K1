import Testing
import Secp256k1
import Foundation

@Suite("Apinotes Tests")
struct Test {
	@Test
	func `C get Swiftified by apinotes file with non-nullability`() {
		var output = [UInt8](repeating: 0, count: 32)
		var x = [UInt8](repeating: 0xde, count: 32)
		let expected = x
		#expect(ecdhHashASN1x963(output: &output, x: &x) == 1)
		#expect(output == expected)
	}
}
