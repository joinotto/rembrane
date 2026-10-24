#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-swift.XXXXXX")
trap 'rm -rf "$build_directory"' EXIT HUP INT TERM

module_cache="$build_directory/module-cache"
mkdir -p "$module_cache"

CLANG_MODULE_CACHE_PATH="$module_cache" swiftc \
    -emit-library \
    -emit-module \
    -module-name Rembrane \
    "$repository_root/sdks/swift/Sources/Rembrane/Rembrane.swift" \
    -emit-module-path "$build_directory/Rembrane.swiftmodule" \
    -o "$build_directory/libRembrane.dylib"

CLANG_MODULE_CACHE_PATH="$module_cache" swiftc \
    -parse-as-library \
    -I "$build_directory" \
    -L "$build_directory" \
    -lRembrane \
    "$repository_root/sdks/swift/Tests/RembraneSmoke/main.swift" \
    -o "$build_directory/rembrane-smoke"

DYLD_LIBRARY_PATH="$build_directory" "$build_directory/rembrane-smoke"
