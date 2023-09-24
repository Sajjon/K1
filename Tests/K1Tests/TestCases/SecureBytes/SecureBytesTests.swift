//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// Modifications: Removed all `#if` and converted error type `CryptoKitError` -> `K1.Error`

import Foundation
@testable import K1
import Testing

@Suite("SecureBytes")
struct SecureBytesTests {
	@Test
	func basicSoundness() {
		var first = SecureBytes()
		var second = SecureBytes()

		first.append(Data("hello".utf8))
		second.append(Data("hello".utf8))

		#expect(first == second)

		first.append(Data("world".utf8))
		second.append(Data("wrold".utf8))
		#expect(first != second)
	}

	@Test
	func simpleCollection() {
		let base = SecureBytes(0 ..< 100)
		#expect(base.count == 100)
		#expect(Array(base) == Array(0 ..< 100))
		#expect(base.first == 0)
		#expect(base.last == 99)
		#expect(base.reduce(Int(0)) { Int($0) + Int($1) } == 4950)
	}

	@Test
	func simpleBidirectionalCollection() {
		let base = SecureBytes(0 ..< 100)
		let reversed = base.reversed()
		#expect(Array(reversed) == Array(stride(from: 99, through: 0, by: -1)))
	}

	@Test
	func simpleRandomAccessCollection() {
		// Not easy to test this, just try to move the indices around a bit.
		let base = SecureBytes(0 ..< 100)
		let aMiddleIndex = base.index(base.startIndex, offsetBy: 48)
		let aDifferentMiddleIndex = base.index(aMiddleIndex, offsetBy: 5)
		#expect(base.distance(from: aMiddleIndex, to: aDifferentMiddleIndex) == 5)

		#expect(base[aMiddleIndex] == 48)
		#expect(base[aDifferentMiddleIndex] == 48 + 5)
	}

	@Test
	func simpleMutableCollection() {
		var base = SecureBytes(repeating: 0, count: 5)
		let offset = base.index(base.startIndex, offsetBy: 2)
		base[offset] = 5
		#expect(Array(base) == [0, 0, 5, 0, 0])
	}

	@Test
	func simpleRangeReplaceableCollection() {
		// This test validates RangeReplaceableCollection and the value semantics all at once.
		let base = SecureBytes(repeating: 0, count: 10)
		let baseBytes = Array(repeating: UInt8(0), count: 10)

		// There are a few ways we can "replace" a subrange. The first is to extend at the front by appending.
		var copy = base
		copy.insert(contentsOf: [1, 2, 3, 4], at: copy.startIndex)
		#expect(Array(copy) == [1, 2, 3, 4] + baseBytes)
		#expect(Array(base) == baseBytes)
		#expect(copy != base)

		// The second is to extend at the back.
		copy = base
		copy.append(contentsOf: [1, 2, 3, 4])
		#expect(Array(copy) == baseBytes + [1, 2, 3, 4])
		#expect(Array(base) == baseBytes)
		#expect(copy != base)

		// The third is to "shrink" by replacing a subrange in the middle.
		copy = base
		var aMiddleIndex = copy.index(copy.startIndex, offsetBy: 2)
		var aDifferentMiddleIndex = copy.index(aMiddleIndex, offsetBy: 5)
		copy.removeSubrange(aMiddleIndex ..< aDifferentMiddleIndex)
		#expect(copy.count == 5)
		#expect(Array(copy) == [0, 0, 0, 0, 0])
		#expect(Array(base) == baseBytes)
		#expect(copy != base)

		// The fourth is to replace a fixed size subrange with a different subrange of the same size.
		copy = base
		aMiddleIndex = copy.index(copy.startIndex, offsetBy: 2)
		aDifferentMiddleIndex = copy.index(aMiddleIndex, offsetBy: 5)
		copy.replaceSubrange(aMiddleIndex ..< aDifferentMiddleIndex, with: [1, 2, 3, 4, 5])
		#expect(copy.count == 10)
		#expect(Array(copy) == [0, 0, 1, 2, 3, 4, 5, 0, 0, 0])
		#expect(Array(base) == baseBytes)
		#expect(copy != base)

		// The fifth is to make the storage bigger.
		copy = base
		aMiddleIndex = copy.index(copy.startIndex, offsetBy: 2)
		aDifferentMiddleIndex = copy.index(aMiddleIndex, offsetBy: 5)
		copy.replaceSubrange(aMiddleIndex ..< aDifferentMiddleIndex, with: [1, 2, 3, 4, 5, 6, 7])
		#expect(copy.count == 12)
		#expect(Array(copy) == [0, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0])
		#expect(Array(base) == baseBytes)
		#expect(copy != base)
	}

	func testResizingByMakingLarger() {
		var base = SecureBytes(count: 12)
		#expect(base.backing.capacity >= 16)
		#expect(base.count == 12)

		base.append(contentsOf: 0 ..< 16)
		#expect(base.backing.capacity >= 32)
		#expect(base.count == 28)

		base.append(contentsOf: 0 ..< 4)
		#expect(base.backing.capacity >= 32)
		#expect(base.count == 32)
	}

	func testCountInitializerGeneratesSomewhatRandomData() {
		let base = SecureBytes(count: 16)
		#expect(base.backing.capacity >= 16)
		#expect(base.count == 16)
		#expect(Array(repeating: UInt8(0), count: 16) != Array(base))
	}

	func testBackingBytesAreAppropriatelySized() {
		var base = SecureBytes(repeating: 0, count: 10)
		#expect(base.backing.capacity >= 16)

		base.withUnsafeBytes { #expect($0.count == 10) }
		base.withUnsafeMutableBytes { #expect($0.count == 10) }
		base.backing._withVeryUnsafeMutableBytes { #expect($0.count >= 16) }
	}

	func testTheresOnlyOneRegion() {
		var base = SecureBytes()
		base.append(Data("hello".utf8))
		base.append(Data("world".utf8))
		#expect(base.regions.count == 1)
	}

	@Test
	func scaryInitializer() {
		let base = SecureBytes(unsafeUninitializedCapacity: 5) { scaryPointer, initializedCapacity in
			#expect(scaryPointer.count == 5)
			scaryPointer.storeBytes(of: UInt32(0x0102_0304).bigEndian, as: UInt32.self)
			initializedCapacity = 4
		}

		#expect(base.backing.capacity >= 8)
		#expect(Array(base) == [1, 2, 3, 4])

		func testThrowingInitialization() throws {
			_ = try SecureBytes(unsafeUninitializedCapacity: 5) { _, _ in
				throw K1.Error.incorrectKeySize
			}
		}
		#expect(throws: K1.Error.incorrectKeySize) {
			try testThrowingInitialization()
		}
	}

	@Test
	func appendingDataPerformsACoW() {
		var base = SecureBytes(repeating: 0, count: 10)
		let copy = base

		base.append("Hello, world".utf8)

		#expect(base.count == 22)
		#expect(copy.count == 10)
	}

	@Test
	func requestingAMutablePointerPerformsACoW() {
		var base = SecureBytes(repeating: 0, count: 10)
		let copy = base

		base.withUnsafeMutableBytes {
			$0.storeBytes(of: UInt32(0x0102_0304).bigEndian, toByteOffset: 4, as: UInt32.self)
		}

		#expect(Array(base) == [0, 0, 0, 0, 1, 2, 3, 4, 0, 0])
		#expect(Array(copy) == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
	}

	@Test
	func dataCausesCoWs() {
		var base = SecureBytes(repeating: 0, count: 10)
		let copy = Data(base)
		#expect(base.count == copy.count)

		base.append("Hello, world".utf8)

		#expect(base.count == 22)
		#expect(copy.count == 10)
	}

	@Test
	func dataFromSlice() {
		var base = SecureBytes(0 ..< 10)
		let copy = Data(base.prefix(5))
		#expect(Array(copy) == [0, 1, 2, 3, 4])

		base.append("Hello, world".utf8)

		#expect(base.count == 22)
		#expect(Array(copy) == [0, 1, 2, 3, 4])
	}
}
