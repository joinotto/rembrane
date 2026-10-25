import json
import unittest

from rembrane import RembraneClient, RembraneError


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

    def test_non_loopback_plain_http_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "HTTPS or an explicit loopback"):
            RembraneClient(
                "http://memory.example.test/v1",
                "token",
                transport=lambda *_: (200, {}, b"{}"),
            )

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


if __name__ == "__main__":
    unittest.main()
