import Foundation
import Secp256k1

// MARK: Format
extension K1.Format {
	/// Bridging value used by libsecp256k1 key specifying the format
	/// of the imported key, i.e. how many bytes.
	var rawValue: UInt32 {
		let value: Int32
		switch self {
		case .compressed: value = SECP256K1_EC_COMPRESSED
		case .uncompressed: value = SECP256K1_EC_UNCOMPRESSED
		}

		return UInt32(value)
	}
}

// MARK: - K1.Format
extension K1 {
	/// Bridging type for: `secp256k1_ec_pubkey_serialize`
	enum Format: UInt32, CaseIterable {
		case compressed, uncompressed
	}
}

extension K1.Format {
	var length: Int {
		switch self {
		case .compressed: return 33
		case .uncompressed: return 65
		}
	}

	init(byteCount: Int) throws {
		if byteCount == Self.uncompressed.length {
			self = .uncompressed
		} else if byteCount == Self.compressed.length {
			self = .compressed
		} else {
			fatalError("invalid byte count: \(byteCount)")
		}
	}
}
