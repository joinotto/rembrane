#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-conformance-inputs.XXXXXX")
trap 'rm -rf "$test_directory"' EXIT

jq 'del(.cases[-1])' \
    "$repository_root/spec/conformance/memory-provider-core.json" \
    >"$test_directory/profile.json"
cp "$repository_root/spec/conformance/memory-provider-core-fixtures.json" \
    "$test_directory/fixtures.json"

for runner in node shell
do
    stderr="$test_directory/$runner.stderr"
    if [ "$runner" = node ]; then
        if REMBRANE_MEMORY_PROVIDER_BASE_URL=https://memory.example.test \
            REMBRANE_MEMORY_PROVIDER_PROFILE_FILE="$test_directory/profile.json" \
            REMBRANE_MEMORY_PROVIDER_FIXTURE_FILE="$test_directory/fixtures.json" \
            node "$repository_root/scripts/run-memory-provider-conformance.mjs" \
                invalid-input >"$test_directory/$runner.stdout" 2>"$stderr"
        then
            echo "Node runner accepted a modified conformance profile" >&2
            exit 1
        fi
    elif REMBRANE_MEMORY_PROVIDER_BASE_URL=https://memory.example.test \
        REMBRANE_MEMORY_PROVIDER_PROFILE_FILE="$test_directory/profile.json" \
        REMBRANE_MEMORY_PROVIDER_FIXTURE_FILE="$test_directory/fixtures.json" \
        "$repository_root/scripts/test-memory-provider-http.sh" \
            invalid-input >"$test_directory/$runner.stdout" 2>"$stderr"
    then
        echo "shell runner accepted a modified conformance profile" >&2
        exit 1
    fi
    if ! rg -F \
        "conformance inputs must match the reviewed profile and fixture" \
        "$stderr" >/dev/null
    then
        echo "$runner runner did not fail at the reviewed-input boundary" >&2
        exit 1
    fi
done

echo "memory provider conformance input binding checks passed"
