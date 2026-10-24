#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-core-offline.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

mkdir -p "$test_directory/crates" "$test_directory/adapters"
for crate in \
    rembrane-application \
    rembrane-config \
    rembrane-contracts \
    rembrane-crypto \
    rembrane-domain \
    rembrane-provider-sdk
do
    cp -R "$repository_root/crates/$crate" "$test_directory/crates/"
done
for adapter in rembrane-semantic-native rembrane-store-memory; do
    cp -R "$repository_root/adapters/$adapter" "$test_directory/adapters/"
done

cat >"$test_directory/Cargo.toml" <<'EOF'
[workspace]
members = [
    "adapters/rembrane-semantic-native",
    "adapters/rembrane-store-memory",
    "crates/rembrane-application",
    "crates/rembrane-config",
    "crates/rembrane-contracts",
    "crates/rembrane-crypto",
    "crates/rembrane-domain",
    "crates/rembrane-provider-sdk",
]
resolver = "2"

[workspace.package]
version = "0.1.0-alpha.1"
edition = "2024"
license = "Apache-2.0"
repository = "https://github.com/mesh-ai-labs/rembrane"
rust-version = "1.88"

[workspace.lints.rust]
unsafe_code = "forbid"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
missing_errors_doc = "allow"
too_many_arguments = "allow"
EOF

(
    cd "$test_directory"
    cargo test --offline
    cargo clippy --offline --all-targets -- -D warnings
)

echo "offline Rembrane core checks passed"
