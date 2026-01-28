import Foundation
import Subprocess
import System

// MARK: - UpdateLibsecpTool
@main
enum UpdateLibsecpTool {
	static func main() async throws {
		print("\n\n✨ Updating submodule libsecp256k1...")
		let cli = try CLI.parse()
		let projectRoot = try await cli.resolveRoot()
		let dryRun = cli.dryRun
		if dryRun {
			print("🌵🏃‍♂️ Running in dry-run mode — we won't perform any changes.")
		} else {
			fatalError("only dry run supported for now")
		}

		let dependencyPath = try readDependencyPath(in: projectRoot)
		let dependencyFullPath = projectRoot.appending(dependencyPath)

		print("📦 Found libsecp256k1 submodule at \(dependencyPath)")

		let currentStatus = try await runCommand(
			"git",
			arguments: ["submodule", "status", "--", dependencyPath],
			workingDirectory: projectRoot
		).stdout.trimmed()

		let currentBranch = try await firstLineOf(
			command: "git",
			arguments: ["branch", "--show-current"],
			workingDirectory: projectRoot
		).trimmed()

		let old = try parseVersionLine(currentStatus)
		print("🏷️ Current libsecp256k1 version: tag \(old.tag), commit \(old.commit)")

		print("🛜 Fetching latest tags in submodule…")
		try await runCommand(
			"git",
			arguments: ["fetch"],
			workingDirectory: dependencyFullPath
		)

		let latestTag = try await firstLineOf(
			command: "git",
			arguments: ["tag", "--list", "v*", "--sort=-v:refname"],
			workingDirectory: dependencyFullPath
		)
		print("🏷️🆕 Latest tag discovered: \(latestTag)")

		print("🏷️🔀 Checking out \(latestTag)…")
		try await runCommand(
			"git",
			arguments: ["checkout", latestTag],
			workingDirectory: dependencyFullPath
		)

		defer {
			// Reset submodule change if dry run
			if dryRun {
				do {
					try await runCommand(
						"git",
						arguments: ["submodule", "update", "--", dependencyPath],
						workingDirectory: dependencyFullPath
					)
				} catch {
					print("❌ Error while resetting submodule changes: \(error)")
				}
			}
			// Switch back to working branch
			do {
				try await runCommand(
					"git",
					arguments: ["switch", currentBranch],
					workingDirectory: dependencyFullPath
				)
			} catch {
				print("❌ Error while switching back to branch '\(currentBranch)': \(error)")
			}
		}

		let newCommit = try await runCommand(
			"git",
			arguments: ["rev-list", "-n", "1", latestTag],
			workingDirectory: dependencyFullPath
		).stdout.trimmed()
		print("#️⃣🆕 New commit resolved from tag: \(newCommit)")

		print("➕📦 Staging submodule changes…")
		try await runCommand(
			"git",
			arguments: ["add", dependencyPath],
			workingDirectory: projectRoot
		)

		print("🧪 Running swift test…")
		try await runCommand(
			"swift",
			arguments: ["test"],
			workingDirectory: projectRoot
		)
		print("🧪 Tests passed🏅.")

		print("📝 Updating README.md…")
		try updateReadme(
			root: projectRoot,
			oldTag: old.tag,
			oldCommit: old.commit,
			newTag: latestTag,
			newCommit: newCommit,
			dryRun: dryRun
		)

		try await runCommand(
			"git",
			arguments: ["add", "README.md"],
			dryRun: dryRun,
			workingDirectory: projectRoot
		)

		let branchName: String
		if dryRun {
			branchName = currentBranch
		} else {
			let newBranch = "bump/libsecp256k1_to_\(latestTag)"
			print("🪾🆕 Creating branch \(newBranch)…")
			try await runCommand(
				"git",
				arguments: ["checkout", "-b", newBranch],
				workingDirectory: projectRoot
			)
			branchName = newBranch
		}

		let commitMessage =
			"Update libsecp256k1 dependency to \(latestTag) (\(newCommit)) [all unit tests passed]"
		print("💾 Committing changes…")
		try await runCommand(
			"git",
			arguments: ["commit", "-m", commitMessage],
			dryRun: dryRun,
			workingDirectory: projectRoot
		)

		print("🛜🪾 Pushing branch to origin…")
		try await runCommand(
			"git",
			arguments: ["push", "--set-upstream", "origin", branchName],
			dryRun: dryRun,
			workingDirectory: projectRoot
		)

		print("✅ Done!")
	}
}

// MARK: - CLI
private struct CLI {
	let rootOverride: FilePath?
	let cwd: FilePath
	let dryRun: Bool

	static func parse() throws -> CLI {
		var args = Array(CommandLine.arguments.dropFirst())
		var rootPath: FilePath?
		var dryRun = false

		while let arg = args.first {
			args.removeFirst()
			switch arg {
			case "--root":
				guard let value = args.first else {
					throw ToolError("Missing value for --root")
				}
				args.removeFirst()
				rootPath = FilePath(value)
			case "--dry-run":
				dryRun = true
			case "--help", "-h":
				print(
					"""
					update-libsecp — updates the libsecp256k1 submodule to the latest tag.

					Options:
						--root <path>   Override project root (defaults to repository root).
						--dry-run       Print actions without mutating the working copy.
						-h, --help      Show this help.
					""")
				exit(0)
			default:
				throw ToolError("Unrecognized argument: \(arg)")
			}
		}

		let cwd = FilePath(FileManager.default.currentDirectoryPath)
		return CLI(rootOverride: rootPath, cwd: cwd, dryRun: dryRun)
	}

	func resolveRoot() async throws -> FilePath {
		if let override = rootOverride {
			return override
		}

		let result = try await run(
			.name("git"),
			arguments: ["rev-parse", "--show-toplevel"],
			workingDirectory: cwd,
			output: .string(limit: 4096),
			error: .string(limit: 4096)
		)

		guard case .exited(0) = result.terminationStatus,
		      let path = result.standardOutput?.trimmed(), !path.isEmpty
		else {
			throw ToolError("Failed to determine git root from \(cwd)")
		}

		return FilePath(path)
	}
}

// MARK: - Core helpers

private func readDependencyPath(in root: FilePath) throws -> String {
	let gitmodulesURL = URL(fileURLWithPath: root.appending(".gitmodules").description)
	let contents = try String(contentsOf: gitmodulesURL)

	for rawLine in contents.split(whereSeparator: \.isNewline) {
		let line = rawLine.trimmingCharacters(in: .whitespaces)
		guard line.hasPrefix("path"), line.contains("libsecp256k1") else { continue }
		let parts = line.split(separator: "=", maxSplits: 1).map {
			$0.trimmingCharacters(in: .whitespaces)
		}
		if parts.count == 2 {
			return parts[1]
		}
	}

	throw ToolError("Could not locate libsecp256k1 path inside .gitmodules")
}

private func parseVersionLine(_ line: String) throws -> (commit: String, tag: String) {
	let pattern = #"[-+ ]?([0-9a-f]{40})\s+[^\(]*\(([^)]+)\)"#
	let regex = try NSRegularExpression(pattern: pattern, options: [])
	let range = NSRange(line.startIndex ..< line.endIndex, in: line)
	guard let match = regex.firstMatch(in: line, options: [], range: range),
	      let commitRange = Range(match.range(at: 1), in: line),
	      let tagRange = Range(match.range(at: 2), in: line)
	else {
		throw ToolError("Unable to parse submodule status line: \(line)")
	}

	return (String(line[commitRange]), String(line[tagRange]))
}

private func updateReadme(
	root: FilePath,
	oldTag: String,
	oldCommit: String,
	newTag: String,
	newCommit: String,
	dryRun: Bool
) throws {
	let readmeURL = URL(fileURLWithPath: root.appending("README.md").description)
	let content = try String(contentsOf: readmeURL)

	let escapedTag = NSRegularExpression.escapedPattern(for: oldTag)
	let escapedCommit = NSRegularExpression.escapedPattern(for: oldCommit)
	let oldLinePattern =
		"> Current `libsecp256k1` version is \\[\(escapedTag) \\(\(escapedCommit)\\)\\]\\([^\\n]*\\)"

	let regex = try NSRegularExpression(pattern: oldLinePattern, options: [])
	let range = NSRange(location: 0, length: (content as NSString).length)

	let replacement =
		"> Current `libsecp256k1` version is [\(newTag) (\(newCommit))](https://github.com/bitcoin-core/secp256k1/releases/tag/\(newTag))"

	let matches = regex.matches(in: content, options: [], range: range)
	guard let match = matches.first else {
		throw ToolError("Could not find README version line to replace.")
	}

	if dryRun {
		print("Skipped README update since dryRun...(but we successfully found the line to replace.)")
	} else {
		let updated = regex.stringByReplacingMatches(
			in: content,
			options: [],
			range: match.range,
			withTemplate: replacement
		)
		try updated.write(to: readmeURL, atomically: true, encoding: String.Encoding.utf8)
	}
}

@discardableResult
private func firstLineOf(
	command executable: String,
	arguments rawArgs: [String],
	dryRun: Bool = false,
	workingDirectory: FilePath
) async throws -> String {
	let (stdout, stderr) = try await runCommand(
		executable,
		arguments: rawArgs,
		dryRun: dryRun,
		workingDirectory: workingDirectory
	)
	guard let firstLine = stdout.split(separator: "\n").first else {
		throw ToolError("No first line returned from command. Output was: \(stdout), stderr: \(stderr)")
	}
	return String(firstLine)
}

@discardableResult
private func runCommand(
	_ executable: String,
	arguments rawArgs: [String],
	dryRun: Bool = false,
	workingDirectory: FilePath
) async throws -> (stdout: String, stderr: String) {
	var rawArgs = rawArgs
	if dryRun {
		rawArgs.append("--dry-run")
	}
	let arguments = Arguments(rawArgs)
	let result = try await run(
		.name(executable),
		arguments: arguments,
		workingDirectory: workingDirectory,
		output: .string(limit: 1_000_000),
		error: .string(limit: 1_000_000)
	)
	print("DEBUG: args \(arguments)")

	guard
		case let .exited(code) = result.terminationStatus,
		code == 0
	else {
		let statusDescription: String
		switch result.terminationStatus {
		case let .exited(code):
			statusDescription = "exit code \(code)"
		case let .unhandledException(signal):
			statusDescription = "terminated by signal \(signal)"
		@unknown default:
			statusDescription = "terminated for unknown reason"
		}

		let failureSeparator = ", "
		let failure = "\(executable) \(arguments)"
		throw ToolError(
			"""
			Command failed: \(failure)
			Status: \(statusDescription)
			Stderr: \(result.standardError ?? "")
			Stdout: \(result.standardOutput ?? "")
			"""
		)
	}

	print("DEBUG: std out \(result.standardOutput)")

	return (result.standardOutput ?? "", result.standardError ?? "")
}

// MARK: - ToolError
private struct ToolError: LocalizedError {
	let message: String
	init(_ message: String) { self.message = message }
	var errorDescription: String? { message }
}

extension String {
	fileprivate func trimmed() -> String {
		trimmingCharacters(in: .whitespacesAndNewlines)
	}
}
