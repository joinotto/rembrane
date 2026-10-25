def exact_keys($expected):
    type == "object" and ((keys | sort) == ($expected | sort));
def required_only_keys($required; $allowed):
    . as $object
    | type == "object"
      and all($required[]; . as $key | $object | has($key))
      and all($object | keys[]; . as $key | $allowed | index($key) != null);
def safe_opaque_id:
    type == "string"
    and length >= 1
    and length <= 255
    and test("^[!-~]+$");
def portable_id:
    type == "string"
    and length >= 2
    and length <= 255
    and test("^[a-z0-9][a-z0-9._-]+$");
def positive_integer:
    type == "number" and . >= 1 and floor == .;
def optional_epoch:
    . == null or positive_integer;
def selector:
    (exact_keys(["scope"]) and .scope == "global")
    or (
        exact_keys(["scope", "domain"])
        and .scope == "domain"
        and (.domain | portable_id)
    )
    or (
        exact_keys(["scope", "entityId"])
        and .scope == "entity"
        and (.entityId | safe_opaque_id)
    )
    or (
        exact_keys(["scope", "activityId"])
        and .scope == "activity"
        and (.activityId | safe_opaque_id)
    );
def evidence:
    exact_keys(["evidenceId", "source"])
    and (.evidenceId | safe_opaque_id)
    and (
        .source == "user_statement"
        or .source == "agent_observation"
        or .source == "tool_result"
        or .source == "imported_record"
        or .source == "workspace_decision"
    );
def disclosure_constraint:
    (
        exact_keys(["type"])
        and (
            .type == "purpose_bound"
            or .type == "no_training"
            or .type == "no_retention"
        )
    )
    or (
        exact_keys(["type", "expiresAtEpochSeconds"])
        and .type == "expires_at"
        and (.expiresAtEpochSeconds | positive_integer)
    );
def context_item:
    required_only_keys(
        [
            "memoryId",
            "version",
            "scope",
            "kind",
            "content",
            "evidence",
            "confidenceMillionths",
            "sensitivity",
            "disclosureConstraints"
        ];
        [
            "memoryId",
            "version",
            "scope",
            "kind",
            "content",
            "evidence",
            "confidenceMillionths",
            "validFromEpochSeconds",
            "validUntilEpochSeconds",
            "sensitivity",
            "disclosureConstraints"
        ]
    )
    and (.memoryId | safe_opaque_id)
    and (.version | positive_integer)
    and (.scope | selector)
    and (
        .kind == "preference"
        or .kind == "semantic"
        or .kind == "episodic"
        or .kind == "procedural"
        or .kind == "observation"
        or .kind == "working"
    )
    and (
        .content
        | type == "string"
          and length >= 1
          and length <= 262144
          and (contains("\u0000") | not)
    )
    and (
        .evidence
        | type == "array"
          and length >= 1
          and length == ([.[] | tojson] | unique | length)
          and all(.[]; evidence)
    )
    and (
        .confidenceMillionths
        | type == "number" and floor == . and . >= 0 and . <= 1000000
    )
    and (
        (has("validFromEpochSeconds") | not)
        or (.validFromEpochSeconds | optional_epoch)
    )
    and (
        (has("validUntilEpochSeconds") | not)
        or (.validUntilEpochSeconds | optional_epoch)
    )
    and (
        .sensitivity == "personal"
        or .sensitivity == "sensitive"
        or .sensitivity == "restricted"
    )
    and (
        .disclosureConstraints
        | type == "array"
          and length == ([.[] | tojson] | unique | length)
          and all(.[]; disclosure_constraint)
    );

exact_keys(["contextPackId", "disclosureId", "items"])
and (.contextPackId | safe_opaque_id)
and (.disclosureId | safe_opaque_id)
and (.items | type == "array" and all(.[]; context_item))
