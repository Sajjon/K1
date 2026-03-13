import SwiftCompilerPlugin
import SwiftSyntaxMacros

@main
struct MyMacrosPlugin: CompilerPlugin {
	let providingMacros: [Macro.Type] = [DeclareSafeApiMacro.self]
}
