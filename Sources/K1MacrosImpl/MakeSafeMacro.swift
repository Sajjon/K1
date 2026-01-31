import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros

public struct MakeSafeMacro: DeclarationMacro {
	public static func expansion(
		of node: some FreestandingMacroExpansionSyntax,
		in context: some MacroExpansionContext
	) throws -> [DeclSyntax] {
		// ---- Parse args: (safeName, unsafeFn, count) ----
		let args = Array(node.arguments)
		guard args.count == 3 else {
			throw MakeSafeMacroError.message(
				#"Expected 3 arguments: #makeSafe("safeName", unsafeFunction, count)"#
			)
		}

		// 1) safeName: allows only "frobnicateThree" (must be String)
		let safeNameExpr = args[0].expression
		let safeName: String = try {
			if let str = safeNameExpr.as(StringLiteralExprSyntax.self) {
				// Accept single-segment string literal
				guard
					str.segments.count == 1,
					let seg = str.segments.first?.as(StringSegmentSyntax.self)
				else {
					throw MakeSafeMacroError.message("safeName must be a simple string literal.")
				}
				return seg.content.text
			}
			if let ref = safeNameExpr.as(DeclReferenceExprSyntax.self) {
				return ref.baseName.text
			}
			throw MakeSafeMacroError.message(
				#"safeName must be a string literal or identifier, e.g. "frobnicateThree" or frobnicateThree"#
			)
		}()

		// 2) unsafeFn: must be an identifier (e.g. frobnicateThreeUnsafe)
		let unsafeExpr = args[1].expression
		guard let unsafeRef = unsafeExpr.as(DeclReferenceExprSyntax.self) else {
			throw MakeSafeMacroError.message(
				#"unsafeFn must be an identifier, e.g. frobnicateThreeUnsafe"#
			)
		}
		let unsafeName = unsafeRef.baseName.text

		// 3) count: must be an integer literal
		let countExpr = args[2].expression
		guard let intLit = countExpr.as(IntegerLiteralExprSyntax.self) else {
			throw MakeSafeMacroError.message(#"count must be an integer literal, e.g. 3"#)
		}
		let countText = intLit.literal.text

		// If count == 0, baseAddress! would be nil
		if let countValue = Int(countText), countValue == 0 {
			throw MakeSafeMacroError.message("count must be >= 1 for this wrapper (uses baseAddress!).")
		}

		let decl: DeclSyntax = """
		@available(macOS 26.0, *)
		func \(raw: safeName)(
			into destination: inout InlineArray<\(raw: countText), UInt8>,
			from source: InlineArray<\(raw: countText), UInt8>
		) {
			var mutableSpan = destination.mutableSpan
			mutableSpan.withUnsafeMutableBufferPointer { dst in
				source.span.withUnsafeBufferPointer { src in
					\(raw: unsafeName)(
						into: dst.baseAddress!,
						from: src.baseAddress!
					)
				}
			}
		}
		"""

		return [decl]
	}
}

// MARK: MakeSafeMacroError
enum MakeSafeMacroError: Error, CustomStringConvertible {
	case message(String)
}

extension MakeSafeMacroError {
	var description: String {
		switch self {
		case let .message(message): return message
		}
	}
}
