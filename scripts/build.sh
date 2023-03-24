#!/bin/bash


set -eu
LIB="Sources/secp256k1/libsecp256k1"
here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$here"/..
rm -rf $LIB

git submodule init
git submodule update
