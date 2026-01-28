import Foundation
import Subprocess
import System

// MARK: - UpdateLibsecpTool
@main
enum UpdateLibsecpTool {
	static func main() async throws {
		print("\n\n✨ Updating submodule libsecp256k1...")
		let cli = try CLI.parse()
		let program = try await Program.from(cli: cli)
		try await program.run()
	}
}

// MARK: - Program
struct Program {
	let dryRun: Bool
	let projectRoot: FilePath
	let dependencyPath: String
}

extension Program {
	var dependencyFullPath: FilePath {
		projectRoot.appending(dependencyPath)
	}

	fileprivate static func from(cli: CLI) async throws -> Self {
		let projectRoot = try await cli.resolveRoot()
		let dryRun = cli.dryRun
		if dryRun {
			print("🌵🏃‍♂️ Running in dry-run mode — we won't perform any changes.")
		} else {
			fatalError("only dry run supported for now")
		}

		let dependencyPath = try readDependencyPath(in: projectRoot)
		print("📦 Found libsecp256k1 submodule at \(dependencyPath)")
		return Self(dryRun: dryRun, projectRoot: projectRoot, dependencyPath: dependencyPath)
	}

	func run() async throws {
		let currentBranch = try await currentBranch()
		let oldVersion = try await getCurrentVersion()
		let latestTag = try await getLatestTag()

		if oldVersion.tag == latestTag {
			print("Current version == latest tag — nothing to update. Exiting ✅.")
			return
		}

		let latestVersion = try await checkout(tag: latestTag)

		do {
			try await proceed(
				branchAtStart: currentBranch,
				latestVersion: latestVersion,
				oldVersion: oldVersion
			)

			await cleanUp(
				currentBranch: currentBranch,
			)
		} catch {
			await cleanUp(
				currentBranch: currentBranch,
				error: error
			)
		}

		print("✅ Done!")
	}

	func proceed(
		branchAtStart: String,
		latestVersion newVersion: Version,
		oldVersion: Version
	) async throws {
		try await stageSubmoduleChangesIfLive()
		try await test()

		try updateReadme(
			oldVersion: oldVersion,
			newVersion: newVersion
		)

		guard !dryRun else {
			print("dryRun: skipping git commands: [add README, checkout branch, commit, push]")
			return
		}

		try await stageReadme()
		let newBranch = try await checkoutNewBranch()
		try await commitChanges(newVersion: newVersion)
		try await push(branch: newBranch)
	}

	func cleanUp(
		currentBranch: String,
		error originalError: Swift.Error? = nil
	) async {
		if let originalError {
			print("Cleaning up due to error: \(originalError)")
		}
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
}

// MARK: Helper Methods
extension Program {
	func test() async throws {
		print("🧪 Running swift test…")
		try await runCommand(
			"swift",
			arguments: ["test"],
			workingDirectory: projectRoot
		)
		print("🧪 Tests passed  ☑️.")
	}

	func submoduleStatus() async throws -> String {
		try await runCommand(
			"git",
			arguments: ["submodule", "status", "--", dependencyPath],
			workingDirectory: projectRoot
		).stdout.trimmed()
	}

	func currentBranch() async throws -> String {
		try await firstLineOf(
			command: "git",
			arguments: ["branch", "--show-current"],
			workingDirectory: projectRoot
		).trimmed()
	}

	func getCurrentVersion() async throws -> Version {
		print("🏷️ Getting current libsecp256k1 version: \(oldVersion)")
		let oldVersion = try await doGetCurrentVersion()
		print("🏷️ Got current libsecp256k1 version: \(oldVersion)")
		return oldVersion
	}

	func doGetCurrentVersion() async throws -> Version {
		let currentStatus = try await submoduleStatus()
		return try parseVersionLine(currentStatus)
	}

	func fetchLatestTags() async throws {
		try await runCommand(
			"git",
			arguments: ["fetch", "--tags", "origin"],
			workingDirectory: dependencyFullPath
		)
	}

	func getLatestTag() async throws -> String {
		print("🛜 Fetching latest tags in submodule…")
		let latestTag = try await doGetLatestTag()
		print("🛜 Fetched latest tag in submodule: \(latestTag) ☑️.")
		return latestTag
	}

	func doGetLatestTag() async throws -> String {
		try await fetchLatestTags()
		return try await firstLineOf(
			command: "git",
			arguments: ["tag", "--list", "v*", "--sort=-v:refname"],
			workingDirectory: dependencyFullPath
		)
	}

	func checkout(tag: String) async throws -> Version {
		print("🏷️🔀 Checking out \(latestTag)…")
		let latestVersion = try await doCheckout(tag: latestTag)
		print("🏷️🔀 Checked out \(latestTag) ☑️.")
		return latestVersion
	}

	func doCheckout(tag: String) async throws -> Version {
		try await runCommand(
			"git",
			arguments: ["checkout", tag],
			workingDirectory: dependencyFullPath
		)
		let commit = try await runCommand(
			"git",
			arguments: ["rev-list", "-n", "1", tag],
			workingDirectory: dependencyFullPath
		).stdout.trimmed()
		print("#️⃣🆕 Commit resolved from tag: \(commit)")
		return Version(tag: tag, commit: commit)
	}

	func stageReadme() async throws {
		print("➕📄 Staging README change…")
		try await stageReadme()
		print("➕📄 Staged README change ☑️.")
	}

	func doStageReadme() async throws {
		try await runCommand(
			"git",
			arguments: ["add", "README.md"],
			workingDirectory: projectRoot
		)
	}

	func checkoutNewBranch() async throws -> String {
		print("🪾🆕 Checked out new branch…")
		let newBranch = try await doCheckoutNewBranch()
		print("🪾🆕 Checked out new branch \(newBranch) ☑️.")
	}

	func doCheckoutNewBranch() async throws -> String {
		let newBranch = "bump/libsecp256k1_to_\(newVersion.tag)"
		try await runCommand(
			"git",
			arguments: ["checkout", "-b", newBranch],
			workingDirectory: projectRoot
		)
		return newBranch
	}

	func commitChanges(newVersion: Version) async throws {
		print("💾 Committing changes…")
		try await doCommitChanges(newVersion: newVersion)
		print("💾 Commited changes ☑️.")
	}

	func doCommitChanges(newVersion: Version) async throws {
		let commitMessage =
			"Update libsecp256k1 dependency to \(newVersion) [all unit tests passed]"
		try await runCommand(
			"git",
			arguments: ["commit", "-m", commitMessage],
			workingDirectory: projectRoot
		)
	}

	func push(branch: String) async throws {
		print("🛜🪾 Pushing branch to origin…")
		try await doPush(branch: newBranch)
		print("🛜🪾 Pushed branch to origin ☑️.")
	}

	func doPush(branch: String) async throws {
		try await runCommand(
			"git",
			arguments: ["push", "--set-upstream", "origin", branch],
			dryRun: dryRun,
			workingDirectory: projectRoot
		)
	}

	func stageSubmoduleChangesIfLive() async throws {
		if dryRun {
			print("➕🌵 Skipping git add of submodule changes since dry run.")
		} else {
			try await stageSubmoduleChanges()
		}
	}

	func stageSubmoduleChanges() async throws {
		print("➕📦 Staging submodule changes…")
		try await doStageSubmoduleChanges()
		print("➕📦 Staged submodule changes ☑️.")
	}

	func doStageSubmoduleChanges() async throws {
		try await runCommand(
			"git",
			arguments: ["add", dependencyPath],
			workingDirectory: projectRoot
		)
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
					"""
				)
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

private func parseVersionLine(_ line: String) throws -> Version {
	let pattern = #"[-+ ]?([0-9a-f]{40})\s+[^\(]*\(([^)]+)\)"#
	let regex = try NSRegularExpression(pattern: pattern, options: [])
	let range = NSRange(line.startIndex ..< line.endIndex, in: line)

	guard
		let match = regex.firstMatch(in: line, options: [], range: range),
		let commitRange = Range(match.range(at: 1), in: line),
		let tagRange = Range(match.range(at: 2), in: line)
	else {
		throw ToolError("Unable to parse submodule status line: \(line)")
	}

	return Version(
		tag: .init(line[tagRange]),
		commit: .init(line[commitRange])
	)
}

// MARK: - Version
struct Version: Equatable {
	let tag: String
	let commit: String
}

extension Program {
	private func updateReadme(
		oldVersion: Version,
		newVersion: Version
	) throws {
		print("📝 Updating README.md…")
		try doUpdateReadme(
			oldVersion: oldVersion,
			newVersion: newVersion
		)
		print("📝 Updated README.md ☑️.")
	}

	private func doUpdateReadme(
		oldVersion: Version,
		newVersion: Version
	) throws {
		let readmeURL = URL(fileURLWithPath: projectRoot.appending("README.md").description)
		let content = try String(contentsOf: readmeURL)

		let escapedTag = NSRegularExpression.escapedPattern(for: oldVersion.tag)
		let escapedCommit = NSRegularExpression.escapedPattern(for: oldVersion.commit)
		let newTag = newVersion.tag
		let oldLinePattern =
			"> Current `libsecp256k1` version is \\[\(escapedTag) \\(\(escapedCommit)\\)\\]\\([^\\n]*\\)"

		let regex = try NSRegularExpression(pattern: oldLinePattern, options: [])
		let range = NSRange(location: 0, length: (content as NSString).length)

		let replacement =
			"> Current `libsecp256k1` version is [\(newTag) (\(newVersion.commit))](https://github.com/bitcoin-core/secp256k1/releases/tag/\(newTag))"

		let matches = regex.matches(in: content, options: [], range: range)
		guard let match = matches.first else {
			throw ToolError("Could not find README version line to replace, searched for line:\n\(oldLinePattern)")
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
			try updated.write(to: readmeURL, atomically: true, encoding: .utf8)
		}
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
		throw ToolError("No first line returned from command. Output was: '\(stdout)', stderr: '\(stderr)'")
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
