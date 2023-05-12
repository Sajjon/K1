import Foundation
import K1

// MARK: - ECSignature
public protocol ECSignature {}

// MARK: - K1.ECDSA.Signature + ECSignature
extension K1.ECDSA.Signature: ECSignature {}

// MARK: - K1.ECDSAWithKeyRecovery.Signature + ECSignature
extension K1.ECDSAWithKeyRecovery.Signature: ECSignature {}
