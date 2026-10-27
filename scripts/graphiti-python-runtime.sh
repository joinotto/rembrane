# Source from Graphiti test runners. Prefer the active environment used by
# `python -m pip`, not a different versioned interpreter elsewhere on PATH.
rembrane_graphiti_python() {
    if test -n "${REMBRANE_GRAPHITI_PYTHON:-}"; then
        if command -v "$REMBRANE_GRAPHITI_PYTHON" >/dev/null 2>&1 &&
            "$REMBRANE_GRAPHITI_PYTHON" -c \
                'import sys; raise SystemExit(sys.version_info < (3, 11))'
        then
            printf '%s\n' "$REMBRANE_GRAPHITI_PYTHON"
            return 0
        fi
        echo "selected Graphiti Python must be available and version 3.11 or newer" >&2
        return 1
    fi
    for candidate in python python3 python3.13 python3.12 python3.11; do
        if command -v "$candidate" >/dev/null 2>&1 &&
            "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))'
        then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    echo "Python 3.11 or newer is required for Graphiti tests" >&2
    return 1
}
