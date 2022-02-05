//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-04.
//

import Foundation
@testable import K1
import XCTest

final class PublicKeyImportTests: XCTestCase {
    func testAssertImportingPublicKeyWithTooFewBytesThrowsError() throws {
        let raw = try Data(hex: "deadbeef")
        assert(
            try PublicKey.import(from: raw),
            throws: K1.Error.incorrectByteCountOfPublicKey(providedByteCount: raw.count)
        )
    }
}
