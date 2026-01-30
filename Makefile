PLATFORM_IOS = iOS Simulator,name=iPhone 11 Pro Max
PLATFORM_MACOS = macOS
PLATFORM_MAC_CATALYST = macOS,variant=Mac Catalyst
PLATFORM_TVOS = tvOS Simulator,name=Apple TV
PLATFORM_WATCHOS = watchOS Simulator,name=Apple Watch Series 7 (45mm)

ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: submodules test dev clean testprod testdebug purge init format formatstaged

rmsubmod:
	rm -rf "$(ROOT_DIR)Sources/secp256k1/libsecp256k1"

clean:
	rm -rf .build

purge:
	make rmsubmod
	make clean

submodules:  ## Update all submodules .
	git submodule update --init
	
init:
	make purge
	make submodules

dev:
	./scripts/bootstrap
	make init

test:
	make clean
	make testdebug
	make clean
	make testprod

testdebug:
	swift test
	
testprod:
	swift test -c release -Xswiftc -enable-testing

formatstaged:
	./scripts/swiftformat-staged

format:
	swiftformat --config .swiftformat "$(ROOT_DIR)"
