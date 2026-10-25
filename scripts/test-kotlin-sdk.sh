#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
client="$repository_root/sdks/kotlin/src/main/kotlin/rembrane/RembraneClient.kt"
smoke="$repository_root/sdks/kotlin/src/test/kotlin/rembrane/Smoke.kt"

test -s "$client"
test -s "$smoke"
rg -q 'HttpClient.Redirect.NEVER' "$client"
rg -q 'Authorization", "Bearer \$token"' "$client"
rg -q 'HTTPS or an explicit loopback URL' "$client"
rg -q 'maximumResponseBytes' "$client"
rg -Fq 'data class ChannelProcessorMessage' "$client"
rg -Fq 'data class ChannelProcessorAcknowledgement' "$client"
rg -Fq 'toByteArray(StandardCharsets.UTF_8).size <= 16_384' "$client"
rg -Fq 'ChannelProcessorStatus.PROCESSED' "$smoke"

if command -v kotlinc >/dev/null 2>&1; then
    build_directory=$(mktemp -d "${TMPDIR:-/tmp}/rembrane-kotlin.XXXXXX")
    trap 'rm -rf "$build_directory"' EXIT HUP INT TERM
    kotlinc "$client" "$smoke" -include-runtime -d "$build_directory/rembrane-smoke.jar"
    java -jar "$build_directory/rembrane-smoke.jar"
fi
