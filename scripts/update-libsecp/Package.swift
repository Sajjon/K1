// swift-tools-version: 6.2

import PackageDescription

let package = Package(
	name: "UpdateLibsecp",
	platforms: [
		.macOS(.v13),
	],
	products: [
		.executable(
			name: "update-libsecp",
			targets: ["UpdateLibsecp"]
		),
	],
	dependencies: [
		.package(
			url: "https://github.com/swiftlang/swift-subprocess",
			from: "0.2.1"
		),
	],
	targets: [
		.executableTarget(
			name: "UpdateLibsecp",
			dependencies: [
				.product(name: "Subprocess", package: "swift-subprocess"),
			]
		),
	]
)
