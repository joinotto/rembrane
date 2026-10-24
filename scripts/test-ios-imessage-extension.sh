#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-ios-imessage.XXXXXX")
trap 'rm -rf "$build_directory"' EXIT HUP INT TERM

simulator_sdk=$(xcrun --sdk iphonesimulator --show-sdk-path)
case $(uname -m) in
    arm64) target=arm64-apple-ios16.0-simulator ;;
    x86_64) target=x86_64-apple-ios16.0-simulator ;;
    *)
        echo "unsupported iOS simulator build architecture" >&2
        exit 1
        ;;
esac

export CLANG_MODULE_CACHE_PATH="$build_directory/clang-cache"
export SWIFT_MODULE_CACHE_PATH="$build_directory/swift-cache"

xcrun swiftc \
    -target "$target" \
    -sdk "$simulator_sdk" \
    -emit-module \
    -module-name Rembrane \
    "$repository_root/sdks/swift/Sources/Rembrane/Rembrane.swift" \
    -emit-module-path "$build_directory/Rembrane.swiftmodule"

xcrun swiftc \
    -target "$target" \
    -sdk "$simulator_sdk" \
    -I "$build_directory" \
    -typecheck \
    "$repository_root/examples/ios-imessage-extension/MessagesViewController.swift"
