#!/bin/sh
set -eu

workflows=.github/workflows

if rg -n '^[[:space:]]*pull_request_target:' "$workflows"; then
    echo "pull_request_target is forbidden for workflows that execute repository code" >&2
    exit 1
fi

if rg -n '^[[:space:]]*permissions:[[:space:]]*write-all' "$workflows"; then
    echo "workflow write-all permissions are forbidden" >&2
    exit 1
fi

if rg -n 'runs-on:[[:space:]]*self-hosted' "$workflows"; then
    echo "unisolated self-hosted runners are forbidden" >&2
    exit 1
fi

if rg -n 'uses:[[:space:]].+@(main|master|HEAD)([[:space:]]|$)' "$workflows"; then
    echo "workflow actions must not use mutable branch references" >&2
    exit 1
fi

if rg -n '(curl|wget)[^|]*[|][[:space:]]*(sh|bash)' "$workflows"; then
    echo "download-and-execute workflow pipelines are forbidden" >&2
    exit 1
fi

write_workflows=$(
    rg -l 'contents:[[:space:]]*write|security-events:[[:space:]]*write' "$workflows" || true
)
for workflow in $write_workflows; do
    case "$workflow" in
        .github/workflows/provider-registry-release.yml|.github/workflows/codeql.yml) ;;
        *)
            echo "unexpected workflow has repository write permission: $workflow" >&2
            exit 1
            ;;
    esac
done

echo "CI security checks passed"
