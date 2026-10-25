#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
registry=${1:-"$repository_root/spec/provider-registry.json"}

for command in jq git; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required provider registry verifier is unavailable: $command" >&2
        exit 1
    fi
done

if [ ! -f "$registry" ]; then
    echo "provider registry does not exist: $registry" >&2
    exit 1
fi

jq -e '
    .generatedAt as $generatedAt
    | .schemaVersion == 1
    and (.generatedAt | fromdateiso8601) <= now
    and (.providers | type == "array")
    and ([.providers[].id] | length == (unique | length))
    and all(
        .providers[];
        (.id | test("^[a-z0-9][a-z0-9._-]+$"))
        and (.adapterVersion | type == "string" and length > 0)
        and (.source.repository | test("^https://[^[:space:]]+$"))
        and (.source.revision | test("^[0-9a-f]{7,64}$"))
        and (.protocolVersions | type == "array" and length > 0)
        and (.deploymentModes | type == "array" and length > 0)
        and (.plaintextProcessing | type == "boolean")
        and (.status | IN("experimental", "compatible", "deprecated"))
        and (.conformance.result | IN("pass", "fail"))
        and .conformance.suiteId == "rembrane.semantic-provider.core"
        and .conformance.suiteVersion == "0.1"
        and .conformance.providerVersion == .adapterVersion
        and .conformance.protocolVersion == "0.1"
        and (. as $provider
            | $provider.protocolVersions
            | contains([$provider.conformance.protocolVersion]))
        and (.conformance.namespace | test("^[A-Za-z0-9._-]{1,100}$"))
        and ([.conformance.cases[].id] == [
            "manifest.compatible",
            "index.visible",
            "workspace.isolated",
            "replacement.exact",
            "stale-delete.preserves-current",
            "exact-delete.propagates"
        ])
        and (
            if .conformance.result == "pass"
            then all(.conformance.cases[]; .result == "pass")
            else any(.conformance.cases[]; .result == "fail")
            end
        )
        and (.conformance.testedAt | fromdateiso8601) <= now
        and (.conformance.testedAt | fromdateiso8601)
            <= ($generatedAt | fromdateiso8601)
        and (
            if .status == "compatible"
            then .conformance.result == "pass"
            else true
            end
        )
    )
' "$registry" >/dev/null

canonical_repository=$(
    git -C "$repository_root" remote get-url origin 2>/dev/null |
        sed -e 's#^git@github.com:#https://github.com/#' -e 's#\.git$##'
)

if [ -n "$canonical_repository" ]; then
    jq -r --arg repository "$canonical_repository" '
        .providers[]
        | select((.source.repository | sub("\\.git$"; "")) == $repository)
        | [.id, .source.revision]
        | @tsv
    ' "$registry" |
        while IFS="$(printf '\t')" read -r provider_id revision; do
            if ! git -C "$repository_root" cat-file -e "${revision}^{commit}" 2>/dev/null; then
                echo "provider $provider_id references unknown local revision: $revision" >&2
                exit 1
            fi
        done
fi

echo "provider registry verified: $registry"
