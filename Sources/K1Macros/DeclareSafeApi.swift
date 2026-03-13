/// # Usage
/// Attach to a (meant to be private) function which accepts `UnsafePointer<UInt8>` in order to
/// generate four functions instead accepting:
/// * `InlineArray<C, UInt8>`
/// * `Span<UInt8>`
/// * `Data`
/// * `[UInt8]`
///
/// ```swift
/// @declareSafeApi(byteCount: 64)
/// static func __nonRecoverableSignature(
/// 	compactBytes: UnsafePointer<UInt8>
/// ) throws -> ECDSASignatureRaw { ... }
/// ```
///
/// # Example
/// ```swift
/// @declareSafeApi(byteCount: 64)
/// static func __nonRecoverableSignature(
/// 	compactBytes: UnsafePointer<UInt8>
/// ) throws -> ECDSASignatureRaw {
/// 	var raw = ECDSASignatureRaw()
///
/// 	try FFI.call(ifFailThrow: .ecdsaSignatureParseCompact) { context in
/// 		parseEcdsaSignatureCompact(
/// 			context: context,
/// 			outputSignature: &raw,
/// 			inputBytes: compactBytes
/// 		)
/// 	}
///
/// 	return raw
/// }
/// ```
///
/// This macro will produce one private helper and four methods meant for
/// public/internal API:
///
/// ```swift
/// @available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
/// static func nonRecoverableSignature(
/// 	compactBytes: InlineArray<64, UInt8>
/// ) throws -> ECDSASignatureRaw {
/// 	try Self.nonRecoverableSignature(compactBytes: compactBytes.span)
/// }
///
/// @available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)
/// static func nonRecoverableSignature(
/// 	compactBytes: Span<UInt8>
/// ) throws -> ECDSASignatureRaw {
/// 	try compactBytes.withUnsafeBytes { pointer in
/// 		try Self._nonRecoverableSignature(compactBytes: pointer)
/// 	}
/// }
///
/// static func nonRecoverableSignature(
/// 	compactBytes: [UInt8]
/// ) throws -> ECDSASignatureRaw {
/// 	try Self._nonRecoverableSignature(compactBytes: compactBytes)
/// }
///
/// static func nonRecoverableSignature(
/// 	compactBytes: Data
/// ) throws -> ECDSASignatureRaw {
/// 	try Self._nonRecoverableSignature(compactBytes: compactBytes)
/// }
///
/// private static func _nonRecoverableSignature(
/// 	compactBytes: some ContiguousBytes
/// ) throws -> ECDSASignatureRaw {
/// 	try compactBytes.withUnsafeBytes { pointer in
/// 		guard pointer.count == 64 else {
/// 			throw K1.Error.incorrectParameterSize
/// 		}
/// 		let bytesPointer = pointer.bindMemory(to: UInt8.self)
/// 		guard let base = bytesPointer.baseAddress else {
/// 			throw K1.Error.invalidParameter
/// 		}
/// 		return try __nonRecoverableSignature(compactBytes: base)
/// 	}
/// }
/// ```
@attached(peer, names: arbitrary)
public macro declareSafeApi(byteCount: Int) = #externalMacro(module: "K1MacrosImpl", type: "DeclareSafeApiMacro")
