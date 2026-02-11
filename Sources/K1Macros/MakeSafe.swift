@freestanding(declaration, names: arbitrary)
public macro makeSafe(_ safeName: Any, _ unsafeFn: Any, _ count: Int) = #externalMacro(module: "K1MacrosImpl", type: "MakeSafeMacro")
