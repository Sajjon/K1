ROOT_DIR := justfile_directory()

default: testdebug

testdebug: 
  swift test --enable-experimental-prebuilts

test: clean testdebug clean testprod

testprod:
	swift test -c release -Xswiftc -enable-testing --enable-experimental-prebuilts

rmsubmod:
	rm -rf "$(ROOT_DIR)Sources/secp256k1/libsecp256k1"

clean:
	rm -rf .build
	rm -rf scripts/update-libsecp/.build

purge: rmsubmod clean

submodules:  ## Update all submodules .
	git submodule update --init

init: purge submodules

typos:
	typos -w

bootstrap:
	./scripts/bootstrap

dev: bootstrap init

synthesize-interface:
	xcrun swift-synthesize-interface -I Sources/secp256k1/include -module-name Secp256k1 -target arm64-apple-macos15 -sdk /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.sdk


format:
	swiftformat --config .swiftformat "{{ROOT_DIR}}"

gyb:
	./scripts/generate_boilerplate_files_with_gyb.sh

bump-dep dryRun="false":
  swift run --enable-experimental-prebuilts \
    --package-path scripts/update-libsecp \
    update-libsecp \
    {{ if dryRun == "true" { "--dry-run" } else { "" } }}
