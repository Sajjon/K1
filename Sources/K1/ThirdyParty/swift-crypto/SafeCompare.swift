// from: https://github.com/apple/swift-crypto/blob/794901c991bf3fa0431ba3c0927ba078799c6911/Sources/Crypto/Util/SafeCompare.swift
// commit: 794901c991bf3fa0431ba3c0927ba078799c6911
// editing done in compliance with Apache License

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


internal func safeCompare<LHS: ContiguousBytes, RHS: ContiguousBytes>(_ lhs: LHS, _ rhs: RHS) -> Bool {
    return openSSLSafeCompare(lhs, rhs)
}
