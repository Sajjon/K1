ROOT_DIR := justfile_directory()

default: testdebug

testdebug: 
  swift test

test: clean testdebug clean testprod

testprod:
	swift test -c release -Xswiftc -enable-testing

rmsubmod:
	rm -rf "$(ROOT_DIR)Sources/secp256k1/libsecp256k1"

clean:
	rm -rf .build
	rm -rf scripts/update-libsecp/.build

purge: rmsubmod clean

submodules:  ## Update all submodules .
	git submodule update --init

init: purge submodules

dev:
	./scripts/bootstrap
	just init

format:
	swiftformat --config .swiftformat "{{ROOT_DIR}}"

gyb:
	./scripts/generate_boilerplate_files_with_gyb.sh

bump-dep dryRun="false":
  swift run \
    --package-path scripts/update-libsecp \
    update-libsecp \
    {{ if dryRun == "true" { "--dry-run" } else { "" } }}
