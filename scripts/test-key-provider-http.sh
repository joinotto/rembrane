#!/bin/sh
set -eu

for command in curl jq mktemp rg base64; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required key-provider conformance tool is unavailable: $command" >&2
        exit 1
    fi
done

base_url=${REMBRANE_KEY_PROVIDER_BASE_URL:-}
token=${REMBRANE_KEY_PROVIDER_TOKEN:-}
namespace=${1:-}

case "$base_url" in
    https://* | http://127.0.0.1:* | http://localhost:* | http://\[::1\]:*) ;;
    *)
        echo "REMBRANE_KEY_PROVIDER_BASE_URL must use HTTPS or loopback HTTP" >&2
        exit 1
        ;;
esac
if [ -z "$token" ] || ! printf '%s' "$token" | rg '^[A-Za-z0-9._~+/=-]+$' >/dev/null; then
    echo "REMBRANE_KEY_PROVIDER_TOKEN must be a non-empty bearer token" >&2
    exit 1
fi
if [ -z "$namespace" ] ||
    ! printf '%s' "$namespace" | rg '^[A-Za-z0-9._-]{1,80}$' >/dev/null
then
    echo "usage: test-key-provider-http.sh <unique-request-namespace>" >&2
    exit 1
fi

test_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-key-provider-http.XXXXXX")
auth_header="$test_directory/auth.header"
response="$test_directory/response.json"
chmod 700 "$test_directory"
printf 'Authorization: Bearer %s\n' "$token" >"$auth_header"
chmod 600 "$auth_header"
trap 'rm -rf "$test_directory"' EXIT HUP INT TERM

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

request GET /v0.1/manifest >"$response"
jq -e '
    .protocolVersion == "0.1"
    and (.providerId | test("^[a-z0-9][a-z0-9._-]+$"))
    and (.algorithms | type == "array" and length > 0)
    and .maximumPlaintextBytes >= 262144
    and .maximumPlaintextBytes <= 1048576
    and (.supportsHistoricalKeys | type == "boolean")
' "$response" >/dev/null
maximum_plaintext_bytes=$(jq -r '.maximumPlaintextBytes' "$response")

unauthorized_status=$(
    curl --silent --output /dev/null --write-out '%{http_code}' \
        "${base_url%/}/v0.1/manifest"
)
test "$unauthorized_status" = "401"

workspace="conformance.workspace.$namespace"
plaintext="rembrane_key_provider_conformance_$namespace"
plaintext_base64=$(printf '%s' "$plaintext" | base64 | tr -d '\n')
seal_request=$(
    jq -cn \
        --arg requestId "seal-$namespace" \
        --arg workspaceId "$workspace" \
        --arg plaintextBase64 "$plaintext_base64" \
        '{
            requestId: $requestId,
            context: {
                workspaceId: $workspaceId,
                recordId: "memory.conformance",
                recordVersion: 1,
                purpose: "memory-content"
            },
            plaintextBase64: $plaintextBase64
        }'
)
printf '%s' "$seal_request" |
    request POST /v0.1/seal \
        --header "Content-Type: application/json" \
        --data-binary @- >"$response"
jq -e '
    (keys | sort) == ["algorithm", "ciphertextBase64", "keyId", "nonceBase64"]
    and all(.ciphertextBase64, .keyId, .algorithm, .nonceBase64;
        type == "string" and length > 0)
' "$response" >/dev/null
envelope=$(cat "$response")

open_request() {
    request_workspace=$1
    request_envelope=$2
    request_suffix=$3
    jq -cn \
        --arg requestId "open-$request_suffix-$namespace" \
        --arg workspaceId "$request_workspace" \
        --argjson envelope "$request_envelope" \
        '{
            requestId: $requestId,
            context: {
                workspaceId: $workspaceId,
                recordId: "memory.conformance",
                recordVersion: 1,
                purpose: "memory-content"
            },
            envelope: $envelope
        }'
}

open_request "$workspace" "$envelope" "roundtrip" |
    request POST /v0.1/open \
        --header "Content-Type: application/json" \
        --data-binary @- >"$response"
jq -e --arg plaintextBase64 "$plaintext_base64" \
    '(keys == ["plaintextBase64"]) and .plaintextBase64 == $plaintextBase64' \
    "$response" >/dev/null

substitution_status=$(
    open_request "conformance.other.$namespace" "$envelope" "substitution" |
        curl --silent --output /dev/null --write-out '%{http_code}' \
            --request POST \
            --header "@$auth_header" \
            --header "Content-Type: application/json" \
            --data-binary @- \
            "${base_url%/}/v0.1/open"
)
test "$substitution_status" = "422"

unknown_envelope=$(printf '%s' "$envelope" | jq '.keyId = "unknown-conformance-key"')
unknown_key_status=$(
    open_request "$workspace" "$unknown_envelope" "unknown-key" |
        curl --silent --output /dev/null --write-out '%{http_code}' \
            --request POST \
            --header "@$auth_header" \
            --header "Content-Type: application/json" \
            --data-binary @- \
            "${base_url%/}/v0.1/open"
)
test "$unknown_key_status" = "422"

oversized_base64=$(
    jq -nr --argjson size "$((maximum_plaintext_bytes + 1))" \
        '"A" * $size | @base64'
)
oversized_request=$(
    printf '%s' "$seal_request" |
        jq --arg requestId "oversized-$namespace" \
            --arg plaintextBase64 "$oversized_base64" \
            '.requestId = $requestId | .plaintextBase64 = $plaintextBase64'
)
oversized_status=$(
    printf '%s' "$oversized_request" |
        curl --silent --output /dev/null --write-out '%{http_code}' \
            --request POST \
            --header "@$auth_header" \
            --header "Content-Type: application/json" \
            --data-binary @- \
            "${base_url%/}/v0.1/seal"
)
case "$oversized_status" in
    413 | 422) ;;
    *) exit 1 ;;
esac

printf '{"protocolVersion":"0.1","result":"pass","namespace":"%s"}\n' "$namespace"
