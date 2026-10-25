#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-provider-registry.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

registry="$repository_root/spec/provider-registry.json"
candidate="$test_root/provider-registry.json"

cp "$registry" "$candidate"
"$repository_root/scripts/verify-provider-registry.sh" "$candidate" >/dev/null

reject_mutation() {
    name=$1
    filter=$2
    jq "$filter" "$registry" >"$candidate"
    if "$repository_root/scripts/verify-provider-registry.sh" "$candidate" \
        >"$test_root/$name.stdout" 2>"$test_root/$name.stderr"
    then
        echo "provider registry accepted invalid evidence mutation: $name" >&2
        exit 1
    fi
}

reject_mutation missing-case 'del(.providers[0].conformance.cases[-1])'
reject_mutation reordered-cases '
    .providers[0].conformance.cases =
        ([.providers[0].conformance.cases[1], .providers[0].conformance.cases[0]]
        + .providers[0].conformance.cases[2:])
'
reject_mutation mismatched-protocol '.providers[0].conformance.protocolVersion = "0.2"'
reject_mutation mismatched-profile-digest \
    '.providers[0].conformance.profileSha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
reject_mutation mismatched-provider-build '
    .providers[0].conformance.providerVersion = "attacker-substituted-build"
'
reject_mutation false-pass '.providers[0].conformance.cases[0].result = "fail"'
reject_mutation unsafe-namespace '.providers[0].conformance.namespace = "cross tenant"'

echo "provider registry validation test passed"
