
// Bridge to C
import secp256k1
import Foundation

extension ECDSASignatureRecoverable {
    /// Initializes ECDSASignatureNonRecoverable from the DER representation.
    public static func `import`<D: DataProtocol>(fromDER derRepresentation: D) throws -> Self {
        let signatureData = try Bridge.importECDSASignature(fromDER: derRepresentation)
        return try Self(rawRepresentation: signatureData)
    }
    
    /// `V||R||S`
    public func rawRepresentation() throws -> Data {
        _rawRepresentation
    }
    
    public func derRepresentation() throws -> Data {
        try Bridge.derRepresentationOfSignature(rawRepresentation: _rawRepresentation)
    }
}

