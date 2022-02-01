//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

import Foundation

public extension Data {
    init(hex: String) throws {
       try self.init(Array<UInt8>(hex: hex))
    }
    
    var bytes: Array<UInt8> {
        Array(self)
    }
    
    func toHexString() -> String {
        self.bytes.toHexString()
    }
}

extension Array {
    init(reserveCapacity: Int) {
        self = Array<Element>()
        self.reserveCapacity(reserveCapacity)
    }
    
    var slice: ArraySlice<Element> {
        self[self.startIndex ..< self.endIndex]
    }
}

extension String {
    func byteArray() throws -> [UInt8] {
        try Array(hex: self)
    }
}

enum BytesError: Swift.Error {
    case stringNotValidHex
}

extension Array where Element == UInt8 {
    public init(hex: String) throws {
        self.init(reserveCapacity: hex.unicodeScalars.lazy.underestimatedCount)
        var buffer: UInt8?
        var skip = hex.hasPrefix("0x") ? 2 : 0
        for char in hex.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                throw BytesError.stringNotValidHex
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                removeAll()
                return
            }
            if let b = buffer {
                append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            append(b)
        }
    }
    
    public func toHexString() -> String {
        `lazy`.reduce(into: "") {
            var s = String($1, radix: 16)
            if s.count == 1 {
                s = "0" + s
            }
            $0 += s
        }
    }
}
