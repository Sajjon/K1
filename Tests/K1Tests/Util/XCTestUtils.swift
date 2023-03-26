import XCTest

extension XCTestCase {
	func assert<T, E: Swift.Error & Equatable>(
		_ fn: @autoclosure () throws -> T,
		throws expectedError: E,
		file: StaticString = #file, line: UInt = #line
	) {
		XCTAssertThrowsError(try fn()) { anyError in
			guard let error = anyError as? E else {
				XCTFail("Incorrect type of error, got errorType: '\(type(of: anyError))' but expected errorType: \(E.self),  got: \(String(describing: anyError))", file: file, line: line)
				return
			}
			XCTAssertEqual(error, expectedError, file: file, line: line)
		}
	}
}
