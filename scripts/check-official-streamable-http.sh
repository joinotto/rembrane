#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repository_root"

mode=${1:---runtime}
if [ "$#" -gt 1 ]; then
    echo "usage: $0 [--build|--runtime]" >&2
    exit 1
fi
case "$mode" in
    --build|--runtime) ;;
    *)
        echo "usage: $0 [--build|--runtime]" >&2
        exit 1
        ;;
esac

for command in cargo jq; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "official MCP SDK readiness checker requires $command" >&2
        exit 1
    }
done

metadata=$(cargo metadata --locked --offline --format-version 1 2>/dev/null) || {
    echo "official MCP SDK dependency metadata is unavailable" >&2
    exit 1
}

printf '%s\n' "$metadata" | jq -e '
    def required_features:
        index("server") != null
        and index("transport-streamable-http-server") != null;
    def normal_edge($id):
        [.deps[]
         | select(.pkg == $id)
         | .dep_kinds[]
         | select(.kind == null and .target == null)]
        | length == 1;
    def normal_declaration:
        .kind == null and .target == null and .optional != true;
    def enabled_target($name; $kind; $features):
        [.targets[]
         | select(.name == $name and .kind == [$kind])
         | select(all((."required-features" // [])[]; . as $feature
                      | ($features | index($feature)) != null))]
        | length == 1;

    "registry+https://github.com/rust-lang/crates.io-index" as $registry
    | [.packages[] | select(.name == "rembrane-mcp")] as $apps
    | [.packages[] | select(.name == "rmcp" and .version == "3.7.0"
                           and .source == $registry)] as $sdks
    | [.packages[] | select(.name == "rembrane-remote-mcp-http")] as $adapters
    | [.resolve.nodes[] | select(.id == $apps[0].id)] as $app_nodes
    | [.resolve.nodes[] | select(.id == $sdks[0].id)] as $sdk_nodes
    | ($apps | length) == 1
    and ($sdks | length) == 1
    and ($adapters | length) == 1
    and ($app_nodes | length) == 1
    and ($sdk_nodes | length) == 1
    and ([$apps[0].dependencies[]
          | select(.name == "rmcp" and .req == "=3.7.0"
                   and .source == $registry and normal_declaration
                   and (.features | required_features))] | length == 1)
    and ([$apps[0].dependencies[]
          | select(.name == "rembrane-remote-mcp-http"
                   and normal_declaration)] | length == 1)
    and ($app_nodes[0] | normal_edge($sdks[0].id))
    and ($app_nodes[0] | normal_edge($adapters[0].id))
    and ($sdk_nodes[0].features | required_features)
    and ($apps[0] | enabled_target("rembrane-mcp"; "bin"; $app_nodes[0].features))
    and ($apps[0] | enabled_target("streamable_http_runtime"; "test"; $app_nodes[0].features))
' >/dev/null 2>&1 || {
    echo "official MCP HTTP readiness requires the pinned registry SDK, normal adapter dependency, and enabled binary/runtime test targets" >&2
    exit 1
}

for target in bin test; do
    case "$target" in
        bin) name=rembrane-mcp ;;
        test) name=streamable_http_runtime ;;
    esac
    cargo check --package rembrane-mcp "--$target" "$name" --locked --offline >/dev/null 2>&1 || {
        echo "official MCP HTTP $target target does not compile from the lockfile" >&2
        exit 1
    }
done

if [ "$mode" = "--build" ]; then
    echo "official MCP HTTP binary and integration target compile; SDK runtime and staging evidence still required"
    exit 0
fi

umask 077
test_output=$(mktemp "${TMPDIR:-/tmp}/rembrane-mcp-runtime.XXXXXX")
trap 'rm -f "$test_output"' EXIT HUP INT TERM

for test_name in \
    sdk_http_two_tenant_encrypted_context_lifecycle \
    sdk_http_denies_cross_tenant_and_scope_substitution \
    sdk_http_session_initialization_and_confirmation \
    sdk_http_session_replacement_and_late_cleanup \
    sdk_http_queued_tool_expiry_and_revocation \
    sdk_http_stream_expiry_and_revocation \
    sdk_http_bounded_admission_and_cancellation \
    sdk_http_redacts_transport_and_provider_failures
do
    cargo test --package rembrane-mcp --test streamable_http_runtime \
        --locked --offline --color never -- "$test_name" \
        --exact --include-ignored --nocapture --color never >"$test_output" 2>&1 || {
        echo "official MCP HTTP runtime test failed: $test_name (diagnostics withheld)" >&2
        exit 1
    }
    summary=$(awk 'NF { last = $0 } END { print last }' "$test_output")
    printf '%s\n' "$summary" | LC_ALL=C grep -Eq \
        '^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9]+\.[0-9]+s$' || {
        echo "official MCP HTTP runtime test must execute exactly once: $test_name (diagnostics withheld)" >&2
        exit 1
    }
done

echo "official MCP HTTP runtime matrix passed; real HTTPS staging and independent review still required"
