def exact_keys($expected):
    type == "object" and ((keys | sort) == ($expected | sort));
def unique_strings:
    type == "array"
    and length == (unique | length)
    and all(.[]; type == "string");
def portable_id:
    type == "string"
    and length >= 2
    and length <= 255
    and test("^[a-z0-9][a-z0-9._-]+$");
def positive_integer:
    type == "number" and . >= 1 and floor == .;

. as $manifest
|
{
    resolve_context: {
        scope: "memory:context:read",
        method: "POST",
        path: "/v1/context/resolve"
    },
    resolve_question: {
        scope: "memory:question:read",
        method: "POST",
        path: "/v1/questions/resolve"
    },
    record_event: {
        scope: "memory:event:write",
        method: "POST",
        path: "/v1/events"
    },
    propose_memory: {
        scope: "memory:proposal:write",
        method: "POST",
        path: "/v1/memory/proposals"
    },
    checkpoint_activity: {
        scope: "memory:checkpoint:write",
        method: "POST",
        path: "/v1/activities/{activity_id}/checkpoint"
    },
    record_disclosure: {
        scope: "memory:disclosure:write",
        method: "POST",
        path: "/v1/disclosures/receipt"
    },
    delete_memory: {
        scope: "memory:memory:delete",
        method: "DELETE",
        path: "/v1/memories/{memory_id}"
    },
    explain_memory: {
        scope: "memory:memory:explain",
        method: "GET",
        path: "/v1/memories/{memory_id}/explain"
    },
    sync_pull: {
        scope: "memory:sync:read",
        method: "GET",
        path: "/v1/sync/pull"
    },
    sync_push: {
        scope: "memory:sync:write",
        method: "POST",
        path: "/v1/sync/push"
    }
} as $bindings
|
exact_keys([
    "providerId",
    "providerVersion",
    "protocolVersion",
    "transports",
    "capabilities",
    "privacyMode",
    "supportedDomains",
    "limits",
    "operations"
])
and (.providerId | portable_id)
and (
    .providerVersion
    | type == "string"
      and length >= 1
      and length <= 100
      and test("^[ -~]+$")
)
and .protocolVersion == "0.1"
and (
    .transports
    | unique_strings
      and length > 0
      and all(.[]; . == "https" or . == "mcp")
)
and (
    .capabilities
    | unique_strings
      and length > 0
      and all(.[]; $bindings[.] != null)
)
and (
    .privacyMode == "end_to_end_encrypted"
    or .privacyMode == "trusted_boundary"
    or .privacyMode == "provider_plaintext"
)
and (
    .supportedDomains
    | unique_strings and all(.[]; portable_id)
)
and (
    .limits
    | exact_keys([
        "maximumContextItems",
        "maximumContextBytes",
        "maximumEventBatchItems",
        "maximumSyncBatchItems"
      ])
      and all(.[]; positive_integer)
)
and (
    .operations
    | type == "array"
      and length > 0
      and length == ([.[] | tojson] | unique | length)
      and all(
          .[];
          exact_keys([
              "operation",
              "capability",
              "oauthScope",
              "httpMethod",
              "pathTemplate"
          ])
          and .operation == .capability
          and $bindings[.operation] != null
          and .oauthScope == $bindings[.operation].scope
          and .httpMethod == $bindings[.operation].method
          and .pathTemplate == $bindings[.operation].path
      )
)
and (
    [$manifest.capabilities[]] | sort
    ==
    ([$manifest.operations[].operation] | sort)
)
and ([$manifest.operations[].oauthScope] | contains($requiredScopes))
