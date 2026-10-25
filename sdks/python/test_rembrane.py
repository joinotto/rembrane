import json
import unittest
from pathlib import Path

from rembrane import (
    RembraneClient,
    RembraneError,
    create_channel_processor_acknowledgement,
    parse_channel_processor_message,
)

SPEC_EXAMPLES = Path(__file__).parents[2] / "spec" / "examples"


class RembraneClientTests(unittest.TestCase):
    def test_audit_request_is_authenticated_and_tenant_explicit(self) -> None:
        calls = []

        def transport(method, url, headers, body, maximum):
            calls.append((method, url, headers, body, maximum))
            return 200, {"Content-Type": "application/json"}, b'{"events":[]}'

        client = RembraneClient(
            "http://127.0.0.1:8787/v1", "test-token", transport=transport
        )
        response = client.list_administrative_audit(
            "team", after_epoch_seconds=10, limit=20
        )

        self.assertEqual(response, {"events": []})
        self.assertEqual(
            calls[0][1],
            "http://127.0.0.1:8787/v1/administrative-audit"
            "?workspaceId=team&afterEpochSeconds=10&limit=20",
        )
        self.assertEqual(calls[0][2]["Authorization"], "Bearer test-token")

    def test_invitation_lifecycle_uses_exact_authenticated_routes(self) -> None:
        calls = []

        def transport(method, url, headers, body, maximum):
            calls.append((method, url, headers, body, maximum))
            return 200, {"Content-Type": "application/json"}, b'{"status":"pending"}'

        client = RembraneClient(
            "http://127.0.0.1:8787/v1", "test-token", transport=transport
        )
        create_request = {
            "workspaceId": "team",
            "invitationId": "invite-1",
            "invitedPrincipalId": "principal-2",
            "role": "member",
            "ttlSeconds": 3600,
            "requestId": "request-1",
        }
        transition_request = {
            "workspaceId": "team",
            "invitationId": "invite-1",
            "requestId": "request-2",
        }

        client.create_workspace_invitation(create_request)
        client.accept_workspace_invitation(transition_request)
        client.revoke_workspace_invitation(
            {**transition_request, "requestId": "request-3"}
        )
        client.list_workspace_invitations("team/name", status="accepted", limit=20)

        expected_paths = (
            "/workspaces/invitations",
            "/workspaces/invitations/accept",
            "/workspaces/invitations/revoke",
        )
        expected_bodies = (
            create_request,
            transition_request,
            {**transition_request, "requestId": "request-3"},
        )
        for call, path, expected_body in zip(calls, expected_paths, expected_bodies):
            self.assertEqual(call[0], "POST")
            self.assertEqual(call[1], f"http://127.0.0.1:8787/v1{path}")
            self.assertEqual(call[2]["Authorization"], "Bearer test-token")
            self.assertEqual(call[2]["Content-Type"], "application/json")
            self.assertEqual(
                call[3],
                json.dumps(expected_body, separators=(",", ":")).encode("utf-8"),
            )
        listing = calls[3]
        self.assertEqual(listing[0], "GET")
        self.assertEqual(
            listing[1],
            "http://127.0.0.1:8787/v1/workspaces/invitations"
            "?workspaceId=team%2Fname&status=accepted&limit=20",
        )
        self.assertEqual(listing[2]["Authorization"], "Bearer test-token")
        self.assertIsNone(listing[3])

    def test_non_loopback_plain_http_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS or an explicit loopback"):
            RembraneClient(
                "http://memory.example.test/v1",
                "token",
                transport=lambda *_: (200, {}, b"{}"),
            )

    def test_graph_context_uses_exact_authenticated_route(self) -> None:
        calls = []

        def transport(method, url, headers, body, maximum):
            calls.append((method, url, headers, body, maximum))
            return (
                200,
                {"Content-Type": "application/json"},
                b'{"disclosureId":"d1","edges":[]}',
            )

        client = RembraneClient(
            "http://127.0.0.1:8787/v1", "test-token", transport=transport
        )
        request = {
            "workspaceId": "team",
            "subjectId": "principal-1",
            "nodeId": "project-1",
            "direction": "outgoing",
            "validAtEpochSeconds": 1_700_000_000,
            "maximumCandidates": 20,
            "purpose": "continue-project",
            "entityId": "project-1",
        }
        response = client.resolve_graph_context(request)

        self.assertEqual(response, {"disclosureId": "d1", "edges": []})
        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(
            calls[0][1],
            "http://127.0.0.1:8787/v1/graph/context/resolve",
        )
        self.assertEqual(calls[0][2]["Authorization"], "Bearer test-token")
        self.assertEqual(
            calls[0][3],
            json.dumps(request, separators=(",", ":")).encode("utf-8"),
        )

    def test_activity_handoff_uses_exact_authenticated_routes(self) -> None:
        calls = []

        def transport(method, url, headers, body, maximum):
            calls.append((method, url, headers, body, maximum))
            return 200, {"Content-Type": "application/json"}, b'{"version":1}'

        client = RembraneClient(
            "http://127.0.0.1:8787/v1", "test-token", transport=transport
        )
        request = {
            "workspaceId": "team",
            "subjectId": "principal-1",
            "goal": "Ship continuity",
            "summary": "SDK checkpoint works.",
            "expectedPreviousSequence": 4,
        }
        client.checkpoint_activity("activity:project-1", request)
        client.resume_activity(
            "activity:project-1",
            "team",
            "principal-1",
            purpose="continue development",
            state_fingerprint="git:abc/123",
        )

        self.assertEqual(calls[0][0], "POST")
        self.assertEqual(
            calls[0][1],
            "http://127.0.0.1:8787/v1/activities/"
            "activity%3Aproject-1/checkpoint",
        )
        self.assertEqual(
            calls[0][3],
            json.dumps(request, separators=(",", ":")).encode("utf-8"),
        )
        self.assertEqual(calls[1][0], "GET")
        self.assertEqual(
            calls[1][1],
            "http://127.0.0.1:8787/v1/activities/"
            "activity%3Aproject-1/resume?workspaceId=team&subjectId=principal-1"
            "&purpose=continue+development&stateFingerprint=git%3Aabc%2F123",
        )
        self.assertIsNone(calls[1][3])
        with self.assertRaisesRegex(ValueError, "bounded opaque identifier"):
            client.checkpoint_activity("unsafe/activity", request)

    def test_memory_lifecycle_uses_exact_authenticated_routes(self) -> None:
        calls = []

        def transport(method, url, headers, body, maximum):
            calls.append((method, url, headers, body, maximum))
            return 200, {"Content-Type": "application/json"}, b'{"version":1}'

        client = RembraneClient(
            "http://127.0.0.1:8787/v1", "test-token", transport=transport
        )
        remember = {
            "workspaceId": "team",
            "subjectId": "principal-1",
            "content": "Call me Hippo",
            "expectedPreviousSequence": 5,
        }
        correction = {
            "workspaceId": "team",
            "subjectId": "principal-1",
            "replacement": "Call me Captain Hippo",
            "expectedVersion": 1,
            "expectedPreviousSequence": 6,
        }
        deletion = {
            "workspaceId": "team",
            "subjectId": "principal-1",
            "reason": "User requested deletion",
            "expectedVersion": 2,
            "expectedPreviousSequence": 7,
        }
        client.remember_preference(remember)
        client.correct_memory("memory:preference-1", correction)
        client.delete_memory("memory:preference-1", deletion)

        self.assertEqual(
            [call[1] for call in calls],
            [
                "http://127.0.0.1:8787/v1/memories/preferences",
                "http://127.0.0.1:8787/v1/memories/"
                "memory%3Apreference-1/correction",
                "http://127.0.0.1:8787/v1/memories/"
                "memory%3Apreference-1/deletion",
            ],
        )
        self.assertEqual(
            [json.loads(call[3]) for call in calls],
            [remember, correction, deletion],
        )
        with self.assertRaisesRegex(ValueError, "bounded opaque identifier"):
            client.correct_memory("../memory", correction)

    def test_problem_response_becomes_typed_error(self) -> None:
        client = RembraneClient(
            "https://memory.example.test/v1",
            "token",
            transport=lambda *_: (
                403,
                {"content-type": "application/json"},
                b'{"code":"access_denied","message":"Access denied"}',
            ),
        )
        with self.assertRaises(RembraneError) as captured:
            client.rotate_workspace_key({"workspaceId": "team"})
        self.assertEqual(captured.exception.status, 403)
        self.assertEqual(captured.exception.code, "access_denied")

    def test_response_limit_is_enforced(self) -> None:
        client = RembraneClient(
            "https://memory.example.test/v1",
            "token",
            maximum_response_bytes=2,
            transport=lambda *_: (
                200,
                {"content-type": "application/json"},
                b'{"ok":true}',
            ),
        )
        with self.assertRaisesRegex(RembraneError, "Response exceeded limit"):
            client.resolve_context({})

    def test_channel_processor_helpers_match_published_fixtures(self) -> None:
        message = json.loads(
            (SPEC_EXAMPLES / "channel-processor-message.json").read_text(
                encoding="utf-8"
            )
        )
        acknowledgement = json.loads(
            (SPEC_EXAMPLES / "channel-processor-acknowledgement.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual(parse_channel_processor_message(message), message)
        self.assertEqual(
            create_channel_processor_acknowledgement(message["eventId"], "processed"),
            acknowledgement,
        )

    def test_channel_processor_helpers_reject_malformed_inputs(self) -> None:
        message = json.loads(
            (SPEC_EXAMPLES / "channel-processor-message.json").read_text(
                encoding="utf-8"
            )
        )
        invalid_messages = (
            None,
            {**message, "protocolVersion": "0.2"},
            {**message, "channel": "sms"},
            {**message, "eventId": "unsafe event"},
            {**message, "workspaceId": "x" * 256},
            {**message, "text": " \n\t"},
            {**message, "text": "😀" * 4_097},
            {**message, "receivedAtEpochSeconds": True},
            {**message, "receivedAtEpochSeconds": 0},
            {**message, "ignored": True},
        )
        for invalid in invalid_messages:
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    ValueError, "Invalid Rembrane channel processor message"
                ):
                    parse_channel_processor_message(invalid)

        with self.assertRaisesRegex(
            ValueError, "Invalid Rembrane channel processor acknowledgement"
        ):
            create_channel_processor_acknowledgement(message["eventId"], "accepted")


if __name__ == "__main__":
    unittest.main()
