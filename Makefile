PLATFORM_IOS = iOS Simulator,name=iPhone 11 Pro Max
PLATFORM_MACOS = macOS
PLATFORM_MAC_CATALYST = macOS,variant=Mac Catalyst
PLATFORM_TVOS = tvOS Simulator,name=Apple TV
PLATFORM_WATCHOS = watchOS Simulator,name=Apple Watch Series 7 (45mm)

default: test-all

test-all: test-library

test-library:
	swift test

format:
	swift format \
		--ignore-unparsable-files \
		--in-place \
		--recursive \
		./Examples ./Package.swift ./Sources ./Tests

.PHONY: format test-all