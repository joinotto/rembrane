#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

script=scripts/check-production-readiness.sh
schema=spec/production-readiness.schema.json
labels_file=$(mktemp "${TMPDIR:-/tmp}/rembrane-readiness-labels.XXXXXX")
trap 'rm -f "$labels_file"' EXIT HUP INT TERM

sed -n 's/^[[:space:]]*record_missing "\([^"]*\)"$/\1/p' "$script" >"$labels_file"

label_count=$(wc -l <"$labels_file" | tr -d ' ')
test "$label_count" -gt 0 || {
    echo "production readiness has no declared missing-gate labels" >&2
    exit 1
}

maximum_labels=$(jq -r '.properties.missing.maxItems' "$schema")
rg -q "^maximum_missing_gates=${maximum_labels}$" "$script" || {
    echo "production readiness runtime gate ceiling differs from its schema" >&2
    exit 1
}
test "$label_count" -le "$maximum_labels" || {
    echo "production readiness exceeds its schema gate-count ceiling" >&2
    exit 1
}

duplicate_count=$(sort "$labels_file" | uniq -d | wc -l | tr -d ' ')
test "$duplicate_count" -eq 0 || {
    echo "production readiness contains duplicate missing-gate labels" >&2
    exit 1
}

maximum_label_bytes=$(jq -r '.properties.missing.items.maxLength' "$schema")
rg -q "^maximum_gate_label_bytes=${maximum_label_bytes}$" "$script" || {
    echo "production readiness runtime label bound differs from its schema" >&2
    exit 1
}
LC_ALL=C awk -v maximum="$maximum_label_bytes" '
    length($0) == 0 || length($0) > maximum {
        exit 1
    }
' "$labels_file" || {
    echo "production readiness contains an empty or oversized gate label" >&2
    exit 1
}

if LC_ALL=C grep -n '[^ -~]' "$labels_file" >/dev/null; then
    echo "production readiness contains a non-printable gate label" >&2
    exit 1
fi

schema_version=$(jq -r '.properties.schemaVersion.const' "$schema")
version_occurrences=$(
    rg -o "\"schemaVersion\":${schema_version}" "$script" | wc -l | tr -d ' '
)
test "$version_occurrences" -eq 2 || {
    echo "production readiness script and schema versions differ" >&2
    exit 1
}

echo "production readiness contract checks passed"
