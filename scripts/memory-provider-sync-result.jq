def exact_keys($expected):
    type == "object" and ((keys | sort) == ($expected | sort));
def safe_opaque_id:
    type == "string"
    and length >= 1
    and length <= 255
    and test("^[!-~]+$");
def positive_integer:
    type == "number" and . >= 1 and floor == .;
def common_change:
    (.changeId | safe_opaque_id)
    and (.sequence | positive_integer)
    and (
        .resource == "memory"
        or .resource == "evidence"
        or .resource == "activity_checkpoint"
        or .resource == "disclosure_receipt"
        or .resource == "entity"
        or .resource == "event"
    )
    and (.resourceId | safe_opaque_id)
    and (.version | positive_integer);
def sync_change:
    (
        exact_keys([
            "changeId",
            "sequence",
            "resource",
            "resourceId",
            "version",
            "operation"
        ])
        and .operation == "delete"
        and common_change
    )
    or (
        exact_keys([
            "changeId",
            "sequence",
            "resource",
            "resourceId",
            "version",
            "operation",
            "payload",
            "payloadSha256"
        ])
        and .operation == "upsert"
        and common_change
        and (
            .payload
            | type == "string"
              and length >= 1
              and length <= 262144
              and (contains("\u0000") | not)
        )
        and (.payloadSha256 | type == "string" and test("^[0-9a-f]{64}$"))
    );

exact_keys(["changes", "nextCursor", "hasMore"])
and (
    .changes
    | type == "array"
      and length == ([.[] | tojson] | unique | length)
      and all(.[]; sync_change)
)
and (
    .nextCursor
    | type == "string"
      and length >= 16
      and length <= 512
      and test("^[A-Za-z0-9_-]+$")
)
and (.hasMore | type == "boolean")
and ((.changes | length) > 0 or (.hasMore | not))
