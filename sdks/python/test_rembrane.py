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
