PLATFORM_IOS = iOS Simulator,name=iPhone 11 Pro Max
PLATFORM_MACOS = macOS
PLATFORM_MAC_CATALYST = macOS,variant=Mac Catalyst
PLATFORM_TVOS = tvOS Simulator,name=Apple TV
PLATFORM_WATCHOS = watchOS Simulator,name=Apple Watch Series 7 (45mm)

ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))

.PHONY: submodules test dev clean

dev:
	./scripts/bootstrap
	make clean
	make submodules

clean:
	rm -rf "$(ROOT_DIR)Sources/secp256k1/libsecp256k1"
	rm -rf .build

submodules:  ## Update all sumodules .
	git submodule update --init

test:
	swift test
