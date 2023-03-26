#!/bin/bash
##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCrypto open source project
##
## Copyright (c) 2020 Apple Inc. and the SwiftCrypto project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.md for the list of SwiftCrypto project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

set -eu
find . -name '*.gyb' |                                               \
    while read file; do                                              \
		swiftfilename="${file%.gyb}";									\
        ./scripts/gyb --line-directive '' -o "$swiftfilename" "$file"; \
        swiftformat "$swiftfilename";									\
		swiftfile="${swiftfilename%.swift}.generated.swift";					\
		mv "$swiftfilename" "$swiftfile";									\
		echo "🔮🐍 GYB generated file: '$swiftfile'";							\
    done
