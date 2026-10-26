#!/bin/sh
set -eu

tracked_files=$(git ls-files)

if printf '%s\n' "$tracked_files" | rg '(^|/)\.env($|\.)' | rg -v '\.env\.example$'; then
    echo "tracked environment file may contain secrets" >&2
    exit 1
fi

if printf '%s\n' "$tracked_files" | rg '\.(pem|key|p12|pfx|jks|keystore)$'; then
    echo "tracked private-key or credential file is forbidden" >&2
    exit 1
fi

if git grep -n -E \
    '(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|sk-proj-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})' \
    -- . \
    ':!scripts/check-sensitive-files.sh'
then
    echo "tracked content resembles a private key, token, or cloud credential" >&2
    exit 1
fi

if rg -n '^#\[derive\([^]]*Debug[^]]*,[[:space:]]*Deserialize' \
    apps/rembrane-mcp/src/lib.rs
then
    echo "MCP tool parameters must not derive plaintext-bearing Debug output" >&2
    exit 1
fi

if rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct ' \
    crates/rembrane-domain/src
then
    echo "domain structs must use an explicitly reviewed redacted Debug implementation" >&2
    exit 1
fi

if rg -n '#\[derive\([^]]*Debug[^]]*\)\]' \
    crates/rembrane-domain/src/identifier.rs
then
    echo "canonical identifier newtypes must not derive raw Debug output" >&2
    exit 1
fi

if ! rg -F 'impl fmt::Debug for $name' \
    crates/rembrane-domain/src/identifier.rs >/dev/null
then
    echo "canonical identifier macro must retain its redacted Debug implementation" >&2
    exit 1
fi

for provider_source in crates/rembrane-provider-sdk/src/*.rs; do
    if sed '/^#\[cfg(test)\]/,$d' "$provider_source" |
        rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
    then
        echo "provider SDK structs must use an explicitly reviewed redacted Debug implementation: $provider_source" >&2
        exit 1
    fi
done

if rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\npub enum (ProviderError|ConformanceFailure|MemoryProviderResponseBody)' \
    crates/rembrane-provider-sdk/src
then
    echo "provider SDK error and generic response enums must retain redacted Debug implementations" >&2
    exit 1
fi

for adapter_source in adapters/*/src/*.rs; do
    if sed '/^#\[cfg(test)\]/,$d' "$adapter_source" |
        rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
    then
        echo "adapter structs must use explicitly reviewed Debug implementations: $adapter_source" >&2
        exit 1
    fi
done

if sed '/^#\[cfg(test)\]/,$d' crates/rembrane-application/src/travel_context.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "travel context structs must use explicitly reviewed redacted Debug implementations" >&2
    exit 1
fi

if sed '/^#\[cfg(test)\]/,$d' crates/rembrane-application/src/import_memory.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "memory import structs must use explicitly reviewed redacted Debug implementations" >&2
    exit 1
fi

for memory_command_source in \
    crates/rembrane-application/src/remember_preference.rs \
    crates/rembrane-application/src/propose_memory.rs \
    crates/rembrane-application/src/revise_memory.rs
do
    if sed '/^#\[cfg(test)\]/,$d' "$memory_command_source" |
        rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
    then
        echo "memory mutation commands must use explicitly reviewed redacted Debug implementations: $memory_command_source" >&2
        exit 1
    fi
done

if sed '/^#\[cfg(test)\]/,$d' crates/rembrane-application/src/checkpoint.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "working-memory checkpoint commands must use explicitly reviewed redacted Debug implementations" >&2
    exit 1
fi

if sed '/^#\[cfg(test)\]/,$d' crates/rembrane-application/src/booking_research.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "booking research commands must use explicitly reviewed redacted Debug implementations" >&2
    exit 1
fi

if sed '/^#\[cfg(test)\]/,$d' adapters/rembrane-remote-mcp-http/src/lib.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "remote MCP HTTP structs must use an explicitly reviewed redacted Debug implementation" >&2
    exit 1
fi

if sed '/^#\[cfg(test)\]/,$d' adapters/rembrane-store-postgres/src/lib.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "PostgreSQL adapter structs must use an explicitly reviewed redacted Debug implementation" >&2
    exit 1
fi

if sed '/^#\[cfg(test)\]/,$d' adapters/rembrane-graph-graphiti/src/lib.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "Graphiti mapping structs must use an explicitly reviewed redacted Debug implementation" >&2
    exit 1
fi

for semantic_adapter in \
    adapters/rembrane-semantic-mem0/src/lib.rs \
    adapters/rembrane-semantic-supermemory/src/lib.rs
do
    if sed '/^#\[cfg(test)\]/,$d' "$semantic_adapter" |
        rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
    then
        echo "external semantic adapter structs must use explicitly reviewed redacted Debug implementations: $semantic_adapter" >&2
        exit 1
    fi
done

if sed '/^#\[cfg(test)\]/,$d' adapters/rembrane-oauth-introspection/src/lib.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "OAuth introspection structs must use explicitly reviewed redacted Debug implementations" >&2
    exit 1
fi

for local_memory_adapter in \
    adapters/rembrane-semantic-native/src/lib.rs \
    adapters/rembrane-graph-native/src/lib.rs \
    adapters/rembrane-store-memory/src/lib.rs
do
    if sed '/^#\[cfg(test)\]/,$d' "$local_memory_adapter" |
        rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
    then
        echo "local memory adapter structs must use count-only reviewed Debug implementations: $local_memory_adapter" >&2
        exit 1
    fi
done

if sed '/^#\[cfg(test)\]/,$d' adapters/rembrane-secret-local/src/lib.rs |
    rg -n -U '#\[derive\([^]]*Debug[^]]*\)\]\n(?:pub )?struct '
then
    echo "local secret resolver structs must use explicitly reviewed non-secret Debug implementations" >&2
    exit 1
fi

echo "sensitive-file checks passed"
