//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

import Foundation
@testable import K1

public extension Data {
    init(hex: String) throws {
       try self.init(Array<UInt8>(hex: hex))
    }
    
}

func swapSignatureByteOrder<D>(_ data: D) throws -> Data where D: DataProtocol {
    guard data.count == 64 || data.count == 65 else {
        throw IncorrectByteCount()
    }
    let invalidByteOrder = Data(data)
    let r = Data(invalidByteOrder[0 ..< 32].reversed())
    let s = Data(invalidByteOrder[32 ..< 64].reversed())

    var vDataOrEmpty = Data()
    if data.count > 64 {
        vDataOrEmpty = Data([invalidByteOrder[64]])
    }

    return r + s + vDataOrEmpty
}
