//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-02-01.
//

import Foundation
@testable import K1

extension Data {
    init(hex: String) throws {
       try self.init(Array<UInt8>(hex: hex))
    }
    
}
