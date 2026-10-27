#!/bin/sh
# Source before setting disposable fixture configuration. Never print values.
# Binary overrides and the local HTTP test address are the only inherited
# Rembrane settings supported by these local lifecycle tests.
local_test_variable_names=$(
    node --input-type=module -e '
        const retained = new Set([
            "REMBRANE_BIN", "REMBRANE_API_BIN", "REMBRANE_MCP_BIN",
            "REMBRANE_TEST_LISTEN",
        ]);
        const names = Object.keys(process.env).filter(
            name => name.startsWith("REMBRANE_") && !retained.has(name),
        );
        if (names.some(name => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))) {
            process.stderr.write("Invalid local-test environment variable name\n");
            process.exit(1);
        }
        process.stdout.write(names.join("\n"));
    '
) || return 1

for local_test_variable_name in $local_test_variable_names; do
    unset "$local_test_variable_name" || return 1
done
unset local_test_variable_name local_test_variable_names

export REMBRANE_KEY_PROVIDER=environment
export REMBRANE_GRAPH_PROVIDER=native
