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

echo "sensitive-file checks passed"
