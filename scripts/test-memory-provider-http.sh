#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required memory provider conformance tool is unavailable: $1" >&2
        exit 1
    fi
}

for command in curl jq mktemp rg openssl sed; do
    require_command "$command"
done

base_url=${REMBRANE_MEMORY_PROVIDER_BASE_URL:-}
primary_token=${REMBRANE_MEMORY_PROVIDER_PRIMARY_TOKEN:-}
other_token=${REMBRANE_MEMORY_PROVIDER_OTHER_TOKEN:-}
readonly_token=${REMBRANE_MEMORY_PROVIDER_READONLY_TOKEN:-}
fixture_file=${REMBRANE_MEMORY_PROVIDER_FIXTURE_FILE:-"$repository_root/spec/conformance/memory-provider-core-fixtures.json"}
profile_file=${REMBRANE_MEMORY_PROVIDER_PROFILE_FILE:-"$repository_root/spec/conformance/memory-provider-core.json"}
namespace=${1:-}

if [ ! -r "$fixture_file" ] || [ ! -r "$profile_file" ]; then
    echo "memory provider conformance profile or fixture file is not readable" >&2
    exit 1
fi
jq -e '
    def bounded_string($maximum):
        type == "string" and length > 0 and length <= $maximum;
    def scope_list:
        type == "array"
        and length > 0
        and length == (unique | length)
        and all(.[]; type == "string" and startswith("memory:"));
    .profileId == "rembrane.memory-provider.core"
    and .protocolVersion == "0.1"
    and (.actors.primary.requiredScopes | scope_list)
    and (.actors.otherWorkspace.requiredScopes | scope_list)
    and (.actors.readOnly.requiredScopes | scope_list)
    and (.scenario.contentPrefix | bounded_string(100))
    and (.scenario.contextPurpose | bounded_string(1000))
    and (.scenario.evidenceSource | bounded_string(100))
    and (.scenario.sourceReference | bounded_string(2048))
    and (.scenario.staleDeleteReason | bounded_string(1000))
    and (.scenario.exactDeleteReason | bounded_string(1000))
    and (.scenario.cleanupDeleteReason | bounded_string(1000))
    and all(
        [
            .scenario.observedAtEpochSeconds,
            .scenario.maximumContextItems,
            .scenario.maximumContextBytes,
            .scenario.maximumSyncItems
        ][];
        type == "number" and . >= 1 and floor == .
    )
' "$fixture_file" >/dev/null
profile_id=$(jq -er '.profileId' "$profile_file")
fixture_profile_id=$(jq -er '.profileId' "$fixture_file")
if [ "$fixture_profile_id" != "$profile_id" ]; then
    echo "memory provider fixture targets a different conformance profile" >&2
    exit 1
fi
profile_sha256=$(
    openssl dgst -sha256 "$profile_file" |
        sed 's/^.*= //'
)
fixture_sha256=$(
    openssl dgst -sha256 "$fixture_file" |
        sed 's/^.*= //'
)
for digest in "$profile_sha256" "$fixture_sha256"; do
    if ! printf '%s' "$digest" | rg '^[0-9a-f]{64}$' >/dev/null; then
        echo "could not calculate memory provider conformance digest" >&2
        exit 1
    fi
done
required_actor_scopes=$(jq -c '
    [
        .actors.primary.requiredScopes[],
        .actors.otherWorkspace.requiredScopes[],
        .actors.readOnly.requiredScopes[]
    ] | unique
' "$fixture_file")
case_results=$(jq -c '
    if .profileId != "rembrane.memory-provider.core"
        or .protocolVersion != "0.1"
        or (.cases | length) == 0
    then error("incompatible memory provider conformance profile")
    else [.cases[] | {id: .id, result: "pass"}]
    end
' "$profile_file")
fixture_id=$(jq -er '.fixtureId' "$fixture_file")
content_prefix=$(jq -er '.scenario.contentPrefix' "$fixture_file")
context_purpose=$(jq -er '.scenario.contextPurpose' "$fixture_file")
evidence_source=$(jq -er '.scenario.evidenceSource' "$fixture_file")
source_reference=$(jq -er '.scenario.sourceReference' "$fixture_file")
observed_at=$(jq -er '.scenario.observedAtEpochSeconds' "$fixture_file")
stale_delete_reason=$(jq -er '.scenario.staleDeleteReason' "$fixture_file")
exact_delete_reason=$(jq -er '.scenario.exactDeleteReason' "$fixture_file")
cleanup_delete_reason=$(jq -er '.scenario.cleanupDeleteReason' "$fixture_file")
fixture_maximum_context_items=$(jq -er '.scenario.maximumContextItems' "$fixture_file")
fixture_maximum_context_bytes=$(jq -er '.scenario.maximumContextBytes' "$fixture_file")
fixture_maximum_sync_items=$(jq -er '.scenario.maximumSyncItems' "$fixture_file")

case "$base_url" in
    https://* | http://127.0.0.1:* | http://localhost:* | http://\[::1\]:*) ;;
    *)
        echo "REMBRANE_MEMORY_PROVIDER_BASE_URL must use HTTPS or loopback HTTP" >&2
        exit 1
        ;;
esac
for token in "$primary_token" "$other_token" "$readonly_token"; do
    if [ -z "$token" ] ||
        ! printf '%s' "$token" | rg '^[A-Za-z0-9._~+/=-]+$' >/dev/null
    then
        echo "all memory provider conformance bearer tokens must be non-empty" >&2
        exit 1
    fi
done
if [ "$primary_token" = "$other_token" ] ||
    [ "$primary_token" = "$readonly_token" ] ||
    [ "$other_token" = "$readonly_token" ]
then
    echo "memory provider conformance tokens must represent distinct connections" >&2
    exit 1
fi
if [ -z "$namespace" ] ||
    ! printf '%s' "$namespace" | rg '^[A-Za-z0-9._-]{1,64}$' >/dev/null
then
    echo "usage: test-memory-provider-http.sh <unique-fixture-namespace>" >&2
    exit 1
fi

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-memory-provider.XXXXXX")
primary_auth="$test_directory/primary.header"
other_auth="$test_directory/other.header"
readonly_auth="$test_directory/readonly.header"
response="$test_directory/response.json"
payload="$test_directory/payload.json"
chmod 700 "$test_directory"
printf 'Authorization: Bearer %s\n' "$primary_token" >"$primary_auth"
printf 'Authorization: Bearer %s\n' "$other_token" >"$other_auth"
printf 'Authorization: Bearer %s\n' "$readonly_token" >"$readonly_auth"
chmod 600 "$primary_auth" "$other_auth" "$readonly_auth"

primary_memory_id=
primary_version=
other_memory_id=
other_version=

request_id() {
    printf 'conformance_%s_%s' "$namespace" "$1" |
        cut -c 1-128
}

call() {
    auth_file=$1
    method=$2
    path=$3
    correlation=$4
    body_file=${5:-}

    set -- \
        --silent --show-error \
        --request "$method" \
        --output "$response" \
        --write-out '%{http_code}' \
        --header "Accept: application/json" \
        --header "X-Rembrane-Request-Id: $(request_id "$correlation")" \
        --header "X-Rembrane-Protocol-Version: 0.1"
    if [ -n "$auth_file" ]; then
        set -- "$@" --header "@$auth_file"
    fi
    if [ -n "$body_file" ]; then
        set -- "$@" \
            --header "Content-Type: application/json" \
            --data-binary "@$body_file"
    fi
    curl "$@" "${base_url%/}$path"
}

encode_path() {
    jq -nr --arg value "$1" '$value | @uri'
}

delete_fixture() {
    auth_file=$1
    memory_id=$2
    version=$3
    label=$4
    if [ -z "$memory_id" ] || [ -z "$version" ]; then
        return
    fi
    jq -cn \
        --arg idempotencyKey "cleanup_${namespace}_${label}" \
        --arg memoryId "$memory_id" \
        --argjson expectedVersion "$version" \
        --arg reason "$cleanup_delete_reason" \
        '{
            idempotencyKey: $idempotencyKey,
            memoryId: $memoryId,
            expectedVersion: $expectedVersion,
            reason: $reason
        }' >"$payload"
    call "$auth_file" DELETE \
        "/v1/memories/$(encode_path "$memory_id")" \
        "cleanup_$label" "$payload" >/dev/null 2>&1 || true
}

cleanup() {
    delete_fixture "$primary_auth" "$primary_memory_id" "$primary_version" primary
    delete_fixture "$other_auth" "$other_memory_id" "$other_version" other
    rm -rf "$test_directory"
}
trap cleanup EXIT HUP INT TERM

status=$(call "" GET /.well-known/ai-memory discovery)
test "$status" = 200
jq -e --argjson requiredScopes "$required_actor_scopes" '
    .protocolVersion == "0.1"
    and ([.capabilities[]] | contains([
        "resolve_context",
        "propose_memory",
        "delete_memory",
        "sync_pull"
    ]))
    and ([.operations[].oauthScope] | contains($requiredScopes))
    and .limits.maximumContextItems > 0
    and .limits.maximumSyncBatchItems > 0
' "$response" >/dev/null
provider_id=$(jq -er '.providerId' "$response")
provider_version=$(jq -er '.providerVersion' "$response")
maximum_context_items=$(jq -r --argjson fixture "$fixture_maximum_context_items" \
    '.limits.maximumContextItems | [., $fixture] | min' "$response")
maximum_context_bytes=$(jq -r --argjson fixture "$fixture_maximum_context_bytes" \
    '.limits.maximumContextBytes | [., $fixture] | min' "$response")
maximum_sync_items=$(jq -r --argjson fixture "$fixture_maximum_sync_items" \
    '.limits.maximumSyncBatchItems | [., $fixture] | min' "$response")

jq -cn \
    --arg purpose "$context_purpose" \
    --arg query "$content_prefix-$namespace" \
    --argjson maximumItems "$maximum_context_items" \
    --argjson maximumBytes "$maximum_context_bytes" \
    '{
        purpose: $purpose,
        query: $query,
        selector: {scope: "global"},
        maximumItems: $maximumItems,
        maximumBytes: $maximumBytes
    }' >"$payload"
status=$(call "" POST /v1/context/resolve missing_token "$payload")
test "$status" = 401

proposal_content="$content_prefix-$namespace-primary"
jq -cn \
    --arg idempotencyKey "proposal_${namespace}_primary" \
    --arg content "$proposal_content" \
    --arg evidenceSource "$evidence_source" \
    --arg sourceReference "$source_reference" \
    --argjson observedAtEpochSeconds "$observed_at" \
    '{
        idempotencyKey: $idempotencyKey,
        selector: {scope: "global"},
        kind: "semantic",
        content: $content,
        evidenceSource: $evidenceSource,
        sourceReference: $sourceReference,
        observedAtEpochSeconds: $observedAtEpochSeconds
    }' >"$payload"
status=$(call "$readonly_auth" POST /v1/memory/proposals insufficient_scope "$payload")
test "$status" = 403

status=$(call "$primary_auth" POST /v1/memory/proposals propose_primary "$payload")
test "$status" = 200
primary_memory_id=$(jq -er '.memoryId | select(length > 0)' "$response")
primary_version=$(jq -er '.version | select(. > 0)' "$response")

status=$(call "$primary_auth" POST /v1/memory/proposals propose_repeat "$payload")
test "$status" = 200
jq -e \
    --arg memoryId "$primary_memory_id" \
    --argjson version "$primary_version" \
    '.memoryId == $memoryId and .version == $version' \
    "$response" >/dev/null

other_content="$content_prefix-$namespace-other"
jq -cn \
    --arg idempotencyKey "proposal_${namespace}_other" \
    --arg content "$other_content" \
    --arg evidenceSource "$evidence_source" \
    --arg sourceReference "$source_reference" \
    --argjson observedAtEpochSeconds "$observed_at" \
    '{
        idempotencyKey: $idempotencyKey,
        selector: {scope: "global"},
        kind: "semantic",
        content: $content,
        evidenceSource: $evidenceSource,
        sourceReference: $sourceReference,
        observedAtEpochSeconds: $observedAtEpochSeconds
    }' >"$payload"
status=$(call "$other_auth" POST /v1/memory/proposals propose_other "$payload")
test "$status" = 200
other_memory_id=$(jq -er '.memoryId | select(length > 0)' "$response")
other_version=$(jq -er '.version | select(. > 0)' "$response")

context_payload() {
    query=$1
    jq -cn \
        --arg purpose "$context_purpose" \
        --arg query "$query" \
        --argjson maximumItems "$maximum_context_items" \
        --argjson maximumBytes "$maximum_context_bytes" \
        '{
            purpose: $purpose,
            query: $query,
            selector: {scope: "global"},
            maximumItems: $maximumItems,
            maximumBytes: $maximumBytes
        }' >"$payload"
}

context_payload "$proposal_content"
status=$(call "$primary_auth" POST /v1/context/resolve context_primary "$payload")
test "$status" = 200
jq -e \
    --arg memoryId "$primary_memory_id" \
    --arg content "$proposal_content" \
    'any(.items[]; .memoryId == $memoryId and .content == $content)' \
    "$response" >/dev/null

status=$(call "$other_auth" POST /v1/context/resolve context_other "$payload")
test "$status" = 200
jq -e \
    --arg memoryId "$primary_memory_id" \
    --arg content "$proposal_content" \
    'all(.items[]; .memoryId != $memoryId and .content != $content)' \
    "$response" >/dev/null

stale_version=$((primary_version + 1))
jq -cn \
    --arg idempotencyKey "delete_${namespace}_stale" \
    --arg memoryId "$primary_memory_id" \
    --argjson expectedVersion "$stale_version" \
    --arg reason "$stale_delete_reason" \
    '{
        idempotencyKey: $idempotencyKey,
        memoryId: $memoryId,
        expectedVersion: $expectedVersion,
        reason: $reason
    }' >"$payload"
status=$(call "$primary_auth" DELETE \
    "/v1/memories/$(encode_path "$primary_memory_id")" \
    delete_stale "$payload")
test "$status" = 409

context_payload "$proposal_content"
status=$(call "$primary_auth" POST /v1/context/resolve context_after_conflict "$payload")
test "$status" = 200
jq -e --arg memoryId "$primary_memory_id" \
    'any(.items[]; .memoryId == $memoryId)' "$response" >/dev/null

status=$(call "$primary_auth" GET \
    "/v1/sync/pull?maximumItems=$maximum_sync_items" sync_primary)
test "$status" = 200
jq -e \
    --arg otherMemoryId "$other_memory_id" \
    '
        (.changes | all(.resourceId != $otherMemoryId))
        and ([.changes[].changeId] | length == (unique | length))
        and all(.changes[]; .sequence > 0)
        and ([.changes[].sequence] == ([.changes[].sequence] | sort))
        and ([.changes[].sequence] | length == (unique | length))
    ' "$response" >/dev/null

jq -cn \
    --arg idempotencyKey "delete_${namespace}_exact" \
    --arg memoryId "$primary_memory_id" \
    --argjson expectedVersion "$primary_version" \
    --arg reason "$exact_delete_reason" \
    '{
        idempotencyKey: $idempotencyKey,
        memoryId: $memoryId,
        expectedVersion: $expectedVersion,
        reason: $reason
    }' >"$payload"
status=$(call "$primary_auth" DELETE \
    "/v1/memories/$(encode_path "$primary_memory_id")" \
    delete_exact "$payload")
test "$status" = 200
jq -e \
    --arg memoryId "$primary_memory_id" \
    --argjson deletedVersion "$primary_version" \
    '
        .memoryId == $memoryId
        and .deletedVersion == $deletedVersion
        and .tombstoneVersion == ($deletedVersion + 1)
    ' "$response" >/dev/null
primary_memory_id=
primary_version=

context_payload "$proposal_content"
status=$(call "$primary_auth" POST /v1/context/resolve context_after_delete "$payload")
test "$status" = 200
jq -e \
    --arg content "$proposal_content" \
    'all(.items[]; .content != $content)' "$response" >/dev/null

jq -cn \
    --arg profileId "$profile_id" \
    --arg profileSha256 "$profile_sha256" \
    --arg fixtureId "$fixture_id" \
    --arg fixtureSha256 "$fixture_sha256" \
    --arg protocolVersion "0.1" \
    --arg providerId "$provider_id" \
    --arg providerVersion "$provider_version" \
    --arg namespace "$namespace" \
    --argjson cases "$case_results" \
    '{
        profileId: $profileId,
        profileSha256: $profileSha256,
        fixtureId: $fixtureId,
        fixtureSha256: $fixtureSha256,
        protocolVersion: $protocolVersion,
        provider: {id: $providerId, version: $providerVersion},
        result: "pass",
        namespace: $namespace,
        cases: $cases
    }'
