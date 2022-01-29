//
//  File.swift
//  
//
//  Created by Alexander Cyon on 2022-01-28.
//

import Foundation

// https://forums.swift.org/t/proposal-property-behaviors/594
internal final class MemoizationBox<T> {
    private let lock = NSLock()
    private var value: T? = nil
    
    internal init() {}
    
    func getOrEvaluate(fn: () -> T) -> T {
        if let value = value { return value }
        // Perform initialization in a thread-safe way.
        return lock.with {
            let initialValue = fn()
            value = initialValue
            return initialValue
        }
    }
}

extension NSLock {

    @discardableResult
    func with<T>(_ block: () throws -> T) rethrows -> T {
        lock()
        defer { unlock() }
        return try block()
    }
}
