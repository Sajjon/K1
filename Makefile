PLATFORM_IOS = iOS Simulator,name=iPhone 11 Pro Max
PLATFORM_MACOS = macOS
PLATFORM_MAC_CATALYST = macOS,variant=Mac Catalyst
PLATFORM_TVOS = tvOS Simulator,name=Apple TV
PLATFORM_WATCHOS = watchOS Simulator,name=Apple Watch Series 7 (45mm)

ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: submodules test

submodules:  ## Update all sumodules .
	rm -rf "$(ROOT_DIR)Sources/secp256k1/libsecp256k1"
	git submodule update --init


test:
	make submodules
	swift test