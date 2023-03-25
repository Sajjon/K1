import Foundation
import K1

// MARK: - ECSignature
public protocol ECSignature {}

// MARK: - K1.ECDSA.NonRecoverable.Signature + ECSignature
extension K1.ECDSA.NonRecoverable.Signature: ECSignature {}

// MARK: - K1.ECDSA.Recoverable.Signature + ECSignature
extension K1.ECDSA.Recoverable.Signature: ECSignature {}
