//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


import Foundation

extension Data {
    public var bytes: [UInt8] {
        withUnsafeBytes { pointer in
            Array(pointer)
        }
    }
}

extension ContiguousBytes {

    @inlinable
    public var bytes: [UInt8] {
        withUnsafeBytes { pointer in
            Array(pointer)
        }
    }
}
