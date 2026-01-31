import SwiftCompilerPlugin
import SwiftSyntaxMacros

@main
struct MyMacrosPlugin: CompilerPlugin {
	let providingMacros: [Macro.Type] = [MakeSafeMacro.self]
}
