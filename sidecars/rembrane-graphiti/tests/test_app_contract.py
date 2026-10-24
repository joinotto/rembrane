import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SOURCE_ROOT = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from rembrane_graphiti.app import _resolve_bearer_token, _validate_token


class AppContractTests(unittest.TestCase):
    def test_rejects_missing_and_header_unsafe_tokens(self):
        for invalid in ("", "token with spaces", "token\r\ninjected:value"):
            with self.assertRaises(RuntimeError):
                _validate_token(invalid)
        _validate_token("opaque-token_123")

    def test_app_module_remains_importable_without_optional_runtime_packages(self):
        source = (SOURCE_ROOT / "rembrane_graphiti" / "app.py").read_text()
        ast.parse(source)
        self.assertNotIn("from fastapi", source.split("def create_app", 1)[0])
        self.assertNotIn("import graphiti_core", source)

    def test_resolves_default_and_selected_environment_tokens(self):
        with patch.dict(
            os.environ,
            {"REMBRANE_GRAPHITI_BEARER_TOKEN": "default-token"},
            clear=True,
        ):
            self.assertEqual(_resolve_bearer_token(), "default-token")
        with patch.dict(
            os.environ,
            {
                "REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE": "env:CUSTOM_TOKEN",
                "CUSTOM_TOKEN": "selected-token",
            },
            clear=True,
        ):
            self.assertEqual(_resolve_bearer_token(), "selected-token")

    @unittest.skipUnless(os.name == "posix", "permission checks require POSIX")
    def test_resolves_only_protected_regular_secret_files(self):
        with tempfile.TemporaryDirectory() as directory:
            secret_path = Path(directory) / "token"
            secret_path.write_bytes(b"protected-token\r\n")
            secret_path.chmod(0o600)
            with patch.dict(
                os.environ,
                {
                    "REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE": (
                        f"file:{secret_path}"
                    )
                },
                clear=True,
            ):
                self.assertEqual(_resolve_bearer_token(), "protected-token")

            secret_path.chmod(0o644)
            with self.assertRaisesRegex(
                RuntimeError, "^Graphiti bearer credential unavailable$"
            ):
                _resolve_bearer_token()

            secret_path.chmod(0o600)
            link_path = Path(directory) / "token-link"
            link_path.symlink_to(secret_path)
            with patch.dict(
                os.environ,
                {
                    "REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE": (
                        f"file:{link_path}"
                    )
                },
                clear=True,
            ), self.assertRaisesRegex(
                RuntimeError, "^Graphiti bearer credential unavailable$"
            ):
                _resolve_bearer_token()

    def test_rejects_inline_unknown_and_invalid_reference_values(self):
        for locator in (
            "inline-token",
            "external:vault:key",
            "env:INVALID-NAME",
            "file:",
        ):
            with self.subTest(locator=locator), patch.dict(
                os.environ,
                {"REMBRANE_GRAPHITI_BEARER_TOKEN_REFERENCE": locator},
                clear=True,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "^Graphiti bearer credential unavailable$"
                ):
                    _resolve_bearer_token()


if __name__ == "__main__":
    unittest.main()
