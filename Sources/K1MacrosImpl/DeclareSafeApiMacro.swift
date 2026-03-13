import Foundation
import SwiftSyntax
import SwiftSyntaxBuilder
import SwiftSyntaxMacros

public struct DeclareSafeApiMacro: PeerMacro {
	public static func expansion(
		of node: AttributeSyntax,
		providingPeersOf declaration: some DeclSyntaxProtocol,
		in context: some MacroExpansionContext
	) throws -> [DeclSyntax] {
		guard let funcDecl = declaration.as(FunctionDeclSyntax.self) else {
			throw DeclareSafeApiMacroError.message("@declareSafeApi can only be attached to a function.")
		}

		let byteCount = try parseByteCount(from: node)
		guard byteCount > 0 else {
			throw DeclareSafeApiMacroError.message("byteCount must be >= 1.")
		}

		if funcDecl.signature.effectSpecifiers?.asyncSpecifier != nil {
			throw DeclareSafeApiMacroError.message("@declareSafeApi does not support async functions.")
		}

		guard let body = funcDecl.body else {
			throw DeclareSafeApiMacroError.message("@declareSafeApi requires a function body.")
		}

		let parameters = funcDecl.signature.parameterClause.parameters
		guard parameters.count == 1, let param = parameters.first else {
			throw DeclareSafeApiMacroError.message("@declareSafeApi currently supports exactly one parameter.")
		}

		guard isUnsafePointerToUInt8(param.type) else {
			throw DeclareSafeApiMacroError.message(
				"Parameter must be UnsafePointer<UInt8>."
			)
		}

		let originalName = funcDecl.name.text
		let hasUnsafePrefix = originalName.hasPrefix("__")
		let publicName = hasUnsafePrefix ? String(originalName.dropFirst(2)) : originalName
		let unsafeName = hasUnsafePrefix ? originalName : "__\(originalName)"
		let internalName = param.secondName?.text ?? (param.firstName.text == "_" ? "bytes" : param.firstName.text)
		let paramDecl = parameterNameClause(firstName: param.firstName.text, secondName: param.secondName?.text, fallback: internalName)
		let callArgString = callArgument(label: param.firstName.text, expr: internalName)

		let effectText = trimmed(funcDecl.signature.effectSpecifiers?.throwsClause?.description ?? "")
		let returnText = trimmed(funcDecl.signature.returnClause?.description ?? "")
		let signatureSuffix = [effectText, returnText].filter { !$0.isEmpty }.joined(separator: " ")
		let signatureSuffixWithSpace = signatureSuffix.isEmpty ? "" : " \(signatureSuffix)"
		let hasReturn = funcDecl.signature.returnClause != nil

		let tryPrefix = effectText.isEmpty ? "" : "try "
		let returnPrefix = hasReturn ? "return " : ""

		let accessModifier = firstAccessModifier(in: funcDecl.modifiers)
		if accessModifier == "private" || accessModifier == "fileprivate" {
			throw DeclareSafeApiMacroError.message(
				"@declareSafeApi cannot be applied to private/fileprivate functions. Use internal/public/open so the generated safe API is visible."
			)
		}
		let nonAccessModifiers = nonAccessModifiers(in: funcDecl.modifiers)
		let wrapperModifiers = modifiersText(access: accessModifier, others: nonAccessModifiers)
		let privateModifiers = modifiersText(access: "private", others: nonAccessModifiers)

		let filteredAttributes = AttributeListSyntax(
			funcDecl.attributes.filter { element in
				guard case .attribute(let attr) = element else { return true }
				let nameText = trimmed(attr.attributeName.description)
				let simpleName = nameText.split(separator: ".").last.map(String.init) ?? nameText
				return simpleName != "declareSafeApi"
			}.map { $0 }
		)
		let attributesText = trimmed(filteredAttributes.description)

		var unsafeDecl: DeclSyntax?
		if !hasUnsafePrefix {
			let unsafeSignature = trimmed(funcDecl.signature.description)
			let unsafeDeclText = """
			\(attributesText.isEmpty ? "" : attributesText + "\n")\
			\(privateModifiers)func \(unsafeName)\(unsafeSignature) \(body.description)
			"""
			unsafeDecl = "\(raw: unsafeDeclText)"
		}

		let helperBodyLine = callLine(
			expr: "\(unsafeName)(\(callArgument(label: param.firstName.text, expr: "base")))",
			tryPrefix: tryPrefix,
			hasReturn: hasReturn
		)
		let helperBody = """
		\(returnPrefix)\(tryPrefix)\(internalName).withUnsafeBytes { pointer in
		\tguard pointer.count == \(byteCount) else {
		\t\tthrow K1.Error.incorrectParameterSize
		\t}
		\tlet bytesPointer = pointer.bindMemory(to: UInt8.self)
		\tguard let base = bytesPointer.baseAddress else {
		\t\tthrow K1.Error.invalidParameter
		\t}
		\t\(helperBodyLine)
		}
		"""

		let helperDecl: DeclSyntax = """
		\(raw: privateModifiers)func _\(raw: publicName)(
			\(raw: paramDecl): some ContiguousBytes
		)\(raw: signatureSuffixWithSpace) {
		\(raw: indent(helperBody, by: 1))
		}
		"""

		let availableAttribute =
			"@available(macOS 26.0, iOS 26.0, tvOS 26.0, watchOS 26.0, *)"

		let inlineArrayBodyLine = callLine(
			expr: "\(publicName)(\(callArgument(label: param.firstName.text, expr: "\(internalName).span")))",
			tryPrefix: tryPrefix,
			hasReturn: hasReturn
		)
		let byteCountText = String(byteCount)
		let inlineArrayDecl: DeclSyntax = """
		\(raw: availableAttribute)
		\(raw: wrapperModifiers)func \(raw: publicName)(
			\(raw: paramDecl): InlineArray<\(raw: byteCountText), UInt8>
		)\(raw: signatureSuffixWithSpace) {
		\t\(raw: inlineArrayBodyLine)
		}
		"""

		let spanBodyLine = callLine(
			expr: "_\(publicName)(\(callArgument(label: param.firstName.text, expr: "pointer")))",
			tryPrefix: tryPrefix,
			hasReturn: hasReturn
		)
		let spanCallLine = """
		\(returnPrefix)\(tryPrefix)\(internalName).withUnsafeBytes { pointer in
		\t\(spanBodyLine)
		}
		"""
		let spanDecl: DeclSyntax = """
		\(raw: availableAttribute)
		\(raw: wrapperModifiers)func \(raw: publicName)(
			\(raw: paramDecl): Span<UInt8>
		)\(raw: signatureSuffixWithSpace) {
		\(raw: indent(spanCallLine, by: 1))
		}
		"""

		let arrayBodyLine = callLine(
			expr: "_\(publicName)(\(callArgString))",
			tryPrefix: tryPrefix,
			hasReturn: hasReturn
		)
		let arrayDecl: DeclSyntax = """
		\(raw: wrapperModifiers)func \(raw: publicName)(
			\(raw: paramDecl): [UInt8]
		)\(raw: signatureSuffixWithSpace) {
		\t\(raw: arrayBodyLine)
		}
		"""

		let dataBodyLine = callLine(
			expr: "_\(publicName)(\(callArgString))",
			tryPrefix: tryPrefix,
			hasReturn: hasReturn
		)
		let dataDecl: DeclSyntax = """
		\(raw: wrapperModifiers)func \(raw: publicName)(
			\(raw: paramDecl): Data
		)\(raw: signatureSuffixWithSpace) {
		\t\(raw: dataBodyLine)
		}
		"""

		var decls: [DeclSyntax] = []
		if let unsafeDecl { decls.append(unsafeDecl) }
		decls.append(contentsOf: [
			helperDecl,
			inlineArrayDecl,
			spanDecl,
			arrayDecl,
			dataDecl,
		])
		return decls
	}
}

// MARK: - Parsing helpers
private func parseByteCount(from node: AttributeSyntax) throws -> Int {
	guard case .argumentList(let args) = node.arguments else {
		throw DeclareSafeApiMacroError.message("Expected arguments: @declareSafeApi(byteCount: 64)")
	}

	guard let byteArg = args.first(where: { $0.label?.text == "byteCount" }) else {
		throw DeclareSafeApiMacroError.message("Missing byteCount: argument.")
	}

	guard let intLit = byteArg.expression.as(IntegerLiteralExprSyntax.self),
		  let value = Int(intLit.literal.text)
	else {
		throw DeclareSafeApiMacroError.message("byteCount must be an integer literal.")
	}

	return value
}

private func isUnsafePointerToUInt8(_ type: TypeSyntax) -> Bool {
	let baseType: TypeSyntax
	if let opt = type.as(OptionalTypeSyntax.self) {
		baseType = opt.wrappedType
	} else if let opt = type.as(ImplicitlyUnwrappedOptionalTypeSyntax.self) {
		baseType = opt.wrappedType
	} else {
		baseType = type
	}

	if let ident = baseType.as(IdentifierTypeSyntax.self),
	   ident.name.text == "UnsafePointer",
	   isUInt8Generic(ident.genericArgumentClause)
	{
		return true
	}

	if let member = baseType.as(MemberTypeSyntax.self),
	   member.name.text == "UnsafePointer",
	   isUInt8Generic(member.genericArgumentClause)
	{
		return true
	}

	return false
}

private func isUInt8Generic(_ clause: GenericArgumentClauseSyntax?) -> Bool {
	guard let clause, clause.arguments.count == 1,
		  let arg = clause.arguments.first
	else { return false }

	switch arg.argument {
	case .type(let typeArg):
		if let ident = typeArg.as(IdentifierTypeSyntax.self), ident.name.text == "UInt8" {
			return true
		}
		if let member = typeArg.as(MemberTypeSyntax.self), member.name.text == "UInt8" {
			return true
		}
		return false
	case .expr:
		return false
	}
}

private func parameterNameClause(firstName: String, secondName: String?, fallback: String) -> String {
	if let secondName {
		return "\(firstName) \(secondName)"
	}
	if firstName == "_" {
		return "_ \(fallback)"
	}
	return firstName
}

private func callArgument(label: String, expr: String) -> String {
	label == "_" ? expr : "\(label): \(expr)"
}

private func modifiersText(access: String?, others: [String]) -> String {
	var parts: [String] = []
	if let access, !access.isEmpty { parts.append(access) }
	parts.append(contentsOf: others.filter { !$0.isEmpty })
	if parts.isEmpty { return "" }
	return parts.joined(separator: " ") + " "
}

private func firstAccessModifier(in modifiers: DeclModifierListSyntax) -> String? {
	for modifier in modifiers {
		let text = trimmed(modifier.name.text)
		if isAccessModifier(text) {
			return text
		}
	}
	return nil
}

private func nonAccessModifiers(in modifiers: DeclModifierListSyntax) -> [String] {
	modifiers.compactMap { modifier in
		let text = trimmed(modifier.description)
		return isAccessModifier(text) ? nil : text
	}
}

private func isAccessModifier(_ text: String) -> Bool {
	switch text {
	case "public", "internal", "fileprivate", "private", "open":
		return true
	default:
		return false
	}
}

private func callLine(expr: String, tryPrefix: String, hasReturn: Bool) -> String {
	let call = "\(tryPrefix)\(expr)"
	return hasReturn ? "return \(call)" : call
}

private func trimmed(_ string: String) -> String {
	string.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func indent(_ text: String, by level: Int) -> String {
	let prefix = String(repeating: "\t", count: level)
	return text
		.split(separator: "\n", omittingEmptySubsequences: false)
		.map { prefix + $0 }
		.joined(separator: "\n")
}

// MARK: - Errors
private enum DeclareSafeApiMacroError: Error, CustomStringConvertible {
	case message(String)

	var description: String {
		switch self {
		case let .message(message): return message
		}
	}
}
