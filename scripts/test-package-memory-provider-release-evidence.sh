#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-memory-package.XXXXXX")

cleanup() {
    rm -rf "$test_root"
}
trap cleanup EXIT HUP INT TERM

profile_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/memory-provider-core.json" |
    awk '{print $NF}')
fixture_sha256=$(openssl dgst -sha256 \
    "$repository_root/spec/conformance/memory-provider-core-fixtures.json" |
    awk '{print $NF}')
jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile | .fixtureSha256 = $fixture' \
    "$repository_root/spec/examples/memory-provider-mixed-version-evidence.json" \
    >"$test_root/mixed.json"
jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile
     | .fixtureSha256 = $fixture
     | .provider.id = "rembrane.packaged-provider"
     | .namespace = "package-provider-a"' \
    "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    >"$test_root/provider-a.json"
jq --arg profile "$profile_sha256" --arg fixture "$fixture_sha256" \
    '.profileSha256 = $profile
     | .fixtureSha256 = $fixture
     | .provider.id = "example.external-packaged-provider"
     | .namespace = "package-provider-b"' \
    "$repository_root/spec/examples/memory-provider-conformance-result.json" \
    >"$test_root/provider-b.json"
openssl genpkey -algorithm Ed25519 \
    -out "$test_root/external-private.pem" >/dev/null 2>&1
openssl pkey -in "$test_root/external-private.pem" -pubout \
    -out "$test_root/external-public.pem" >/dev/null 2>&1
openssl pkeyutl -sign -inkey "$test_root/external-private.pem" -rawin \
    -in "$test_root/provider-b.json" -out "$test_root/provider-b.json.sig"

packager="$repository_root/scripts/package-memory-provider-release-evidence.mjs"
node "$packager" \
    "$test_root/evidence" \
    1111111111111111111111111111111111111111 \
    2026-01-15T12:00:00Z \
    "$test_root/mixed.json" \
    "$test_root/provider-a.json" \
    in-repository \
    rembrane-maintainers \
    2222222222222222222222222222222222222222 \
    "$test_root/provider-b.json" \
    external \
    independent-provider-maintainer \
    3333333333333333333333333333333333333333 \
    "$test_root/provider-b.json.sig" \
    "$test_root/external-public.pem" >/dev/null

node "$repository_root/scripts/verify-memory-provider-release-evidence.mjs" \
    "$test_root/evidence" "$test_root/external-public.pem" >/dev/null
test "$(find "$test_root/evidence" -type f | wc -l | tr -d ' ')" -eq 7
if stat -f '%Lp' "$test_root/evidence" >/dev/null 2>&1; then
    directory_mode=$(stat -f '%Lp' "$test_root/evidence")
else
    directory_mode=$(stat -c '%a' "$test_root/evidence")
fi
test "$directory_mode" = 700
find "$test_root/evidence" -type f -exec sh -c '
    for file do
        if stat -f "%Lp" "$file" >/dev/null 2>&1; then
            mode=$(stat -f "%Lp" "$file")
        else
            mode=$(stat -c "%a" "$file")
        fi
        test "$mode" = 600 || exit 1
    done
' sh {} +

if node "$packager" \
    "$test_root/evidence" \
    1111111111111111111111111111111111111111 \
    2026-01-15T12:00:00Z \
    "$test_root/mixed.json" \
    "$test_root/provider-a.json" \
    in-repository \
    rembrane-maintainers \
    2222222222222222222222222222222222222222 \
    "$test_root/provider-b.json" \
    external \
    independent-provider-maintainer \
    3333333333333333333333333333333333333333 \
    "$test_root/provider-b.json.sig" \
    "$test_root/external-public.pem" >/dev/null 2>&1
then
    echo "release packager overwrote an existing evidence directory" >&2
    exit 1
fi

ln -s "$test_root/provider-b.json" "$test_root/provider-b-link.json"
if node "$packager" \
    "$test_root/symbolic" \
    1111111111111111111111111111111111111111 \
    2026-01-15T12:00:00Z \
    "$test_root/mixed.json" \
    "$test_root/provider-a.json" \
    in-repository \
    rembrane-maintainers \
    2222222222222222222222222222222222222222 \
    "$test_root/provider-b-link.json" \
    external \
    independent-provider-maintainer \
    3333333333333333333333333333333333333333 \
    "$test_root/provider-b.json.sig" \
    "$test_root/external-public.pem" >/dev/null 2>&1
then
    echo "release packager accepted symbolic provider evidence" >&2
    exit 1
fi
test ! -e "$test_root/symbolic"

printf '%s\n' '{"not":"a conformance result"}' \
    >"$test_root/invalid-provider.json"
openssl pkeyutl -sign -inkey "$test_root/external-private.pem" -rawin \
    -in "$test_root/invalid-provider.json" \
    -out "$test_root/invalid-provider.json.sig"
if node "$packager" \
    "$test_root/verification-failure" \
    1111111111111111111111111111111111111111 \
    2026-01-15T12:00:00Z \
    "$test_root/mixed.json" \
    "$test_root/provider-a.json" \
    in-repository \
    rembrane-maintainers \
    2222222222222222222222222222222222222222 \
    "$test_root/invalid-provider.json" \
    external \
    independent-provider-maintainer \
    3333333333333333333333333333333333333333 \
    "$test_root/invalid-provider.json.sig" \
    "$test_root/external-public.pem" >/dev/null 2>&1
then
    echo "release packager accepted an invalid provider result" >&2
    exit 1
fi
test ! -e "$test_root/verification-failure"

echo "memory-provider release evidence packaging checks passed"
