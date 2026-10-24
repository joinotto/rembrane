#!/bin/sh
set -eu

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required provider conformance tool is unavailable: $1" >&2
        exit 1
    fi
}

for command in curl jq mktemp rg; do
    require_command "$command"
done

base_url=${REMBRANE_PROVIDER_BASE_URL:-}
token=${REMBRANE_PROVIDER_TOKEN:-}
namespace=${1:-}

case "$base_url" in
    https://* | http://127.0.0.1:* | http://localhost:* | http://\[::1\]:*) ;;
    *)
        echo "REMBRANE_PROVIDER_BASE_URL must use HTTPS or loopback HTTP" >&2
        exit 1
        ;;
esac
if [ -z "$token" ] || ! printf '%s' "$token" | rg '^[A-Za-z0-9._~+/=-]+$' >/dev/null; then
    echo "REMBRANE_PROVIDER_TOKEN must be a non-empty bearer token" >&2
    exit 1
fi
if [ -z "$namespace" ] ||
    ! printf '%s' "$namespace" | rg '^[A-Za-z0-9._-]{1,80}$' >/dev/null
then
    echo "usage: test-provider-http.sh <unique-fixture-namespace>" >&2
    exit 1
fi

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-provider-http.XXXXXX")
auth_header="$test_directory/auth.header"
response="$test_directory/response.json"
chmod 700 "$test_directory"
printf 'Authorization: Bearer %s\n' "$token" >"$auth_header"
chmod 600 "$auth_header"

workspace="conformance.workspace.$namespace"
other_workspace="conformance.other.$namespace"
memory_id="conformance.memory.$namespace"
first_token="rembrane_conformance_${namespace}_v1"
second_token="rembrane_conformance_${namespace}_v2"

request() {
    method=$1
    path=$2
    shift 2
    curl --silent --show-error --fail-with-body \
        --request "$method" \
        --header "@$auth_header" \
        --header "Accept: application/json" \
        "$@" \
        "${base_url%/}$path"
}

cleanup() {
    request DELETE \
        "/v0.1/projections/$workspace/$memory_id?throughVersion=2" \
        --header "Idempotency-Key: cleanup-$namespace" >/dev/null 2>&1 || true
    rm -rf "$test_directory"
}
trap cleanup EXIT HUP INT TERM

request GET /v0.1/manifest >"$response"
jq -e '
    .protocolVersion == "0.1"
    and ([.capabilities[]] | contains([
        "index",
        "search",
        "delete",
        "workspace-filter",
        "versioned-records"
    ]))
    and .limits.maximumContentBytes > 0
    and .limits.maximumCandidates > 0
' "$response" >/dev/null
maximum_candidates=$(jq -r '.limits.maximumCandidates | [., 10] | min' "$response")

projection() {
    version=$1
    content=$2
    jq -cn \
        --arg workspaceId "$workspace" \
        --arg memoryId "$memory_id" \
        --argjson version "$version" \
        --arg content "$content" \
        '{
            workspaceId: $workspaceId,
            memoryId: $memoryId,
            version: $version,
            scope: {type: "global"},
            kind: "semantic",
            content: $content
        }'
}

search() {
    search_workspace=$1
    query=$2
    jq -cn \
        --arg workspaceId "$search_workspace" \
        --arg query "$query" \
        --argjson maximumCandidates "$maximum_candidates" \
        '{
            workspaceId: $workspaceId,
            query: $query,
            maximumCandidates: $maximumCandidates
        }' |
        request POST /v0.1/search \
            --header "Content-Type: application/json" \
            --data-binary @-
}

projection 1 "$first_token" |
    request PUT /v0.1/projections \
        --header "Content-Type: application/json" \
        --header "Idempotency-Key: upsert-v1-$namespace" \
        --data-binary @- >/dev/null
search "$workspace" "$first_token" >"$response"
jq -e \
    --arg memoryId "$memory_id" \
    'any(.candidates[]; .memoryId == $memoryId and .version == 1)' \
    "$response" >/dev/null
search "$other_workspace" "$first_token" >"$response"
jq -e \
    --arg memoryId "$memory_id" \
    'all(.candidates[]; .memoryId != $memoryId)' \
    "$response" >/dev/null

projection 2 "$second_token" |
    request PUT /v0.1/projections \
        --header "Content-Type: application/json" \
        --header "Idempotency-Key: upsert-v2-$namespace" \
        --data-binary @- >/dev/null
search "$workspace" "$second_token" >"$response"
jq -e \
    --arg memoryId "$memory_id" \
    'any(.candidates[]; .memoryId == $memoryId and .version == 2)
        and all(.candidates[]; .memoryId != $memoryId or .version == 2)' \
    "$response" >/dev/null
search "$workspace" "$first_token" >"$response"
jq -e \
    --arg memoryId "$memory_id" \
    'all(.candidates[]; .memoryId != $memoryId)' \
    "$response" >/dev/null

request DELETE \
    "/v0.1/projections/$workspace/$memory_id?throughVersion=1" \
    --header "Idempotency-Key: delete-v1-$namespace" >/dev/null
search "$workspace" "$second_token" >"$response"
jq -e \
    --arg memoryId "$memory_id" \
    'any(.candidates[]; .memoryId == $memoryId and .version == 2)' \
    "$response" >/dev/null

request DELETE \
    "/v0.1/projections/$workspace/$memory_id?throughVersion=2" \
    --header "Idempotency-Key: delete-v2-$namespace" >/dev/null
search "$workspace" "$second_token" >"$response"
jq -e \
    --arg memoryId "$memory_id" \
    'all(.candidates[]; .memoryId != $memoryId)' \
    "$response" >/dev/null

printf '{"protocolVersion":"0.1","result":"pass","namespace":"%s"}\n' "$namespace"
