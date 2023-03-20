//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-27.
//


import Foundation


extension ContiguousBytes {

    @inlinable
    var bytes: [UInt8] {
        withUnsafeBytes { pointer in
            Array(pointer)
        }
    }
}
