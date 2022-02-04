//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-04.
//

import Foundation
import Foundation
@testable import K1
import XCTest

extension XCTestCase {
    func assert<T, E: Swift.Error & Equatable>(
        _ fn: @autoclosure () throws -> T,
        throws expectedError: E,
        file: StaticString = #file, line: UInt = #line
    ) {
        XCTAssertThrowsError(try fn()) { anyError in
            guard let error = anyError as? E else {
                XCTFail("Incorrect type of error, got '\(type(of: anyError))' but expected: \(E.self)")
                return
            }
            XCTAssertEqual(error, expectedError)
        }
    }
}

final class PrivateKeyImportTests: XCTestCase {

    func testImportTooFewBytesThrowsError() throws {
        let raw = try Data(hex: "deadbeef")
        assert(
            try PrivateKey.import(rawRepresentation: raw),
            throws: K1.Error.invalidSizeOfPrivateKey(providedByteCount: raw.count)
        )
    }
    
}
