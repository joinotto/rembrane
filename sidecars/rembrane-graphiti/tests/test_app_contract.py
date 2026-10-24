import ast
import sys
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))

from rembrane_graphiti.app import _validate_token


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


if __name__ == "__main__":
    unittest.main()
