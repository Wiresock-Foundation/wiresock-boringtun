"""Fail-closed attribution checks, including optimized Python execution."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


class AttributionTests(unittest.TestCase):
    def checker(self, root):
        path = ROOT / "scripts/check-attribution.py"
        namespace = {"__file__": str(path), "__name__": "attribution_test"}
        exec(compile(path.read_text(), str(path), "exec", optimize=1), namespace)
        namespace["ROOT"] = root
        return namespace["check"]

    def test_optimized_python_rejects_bad_license(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE.md").write_text("invalid license\n")
            with patch("subprocess.check_output", return_value=""), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "original license"):
                    self.checker(root)()

    def test_unreadable_source_does_not_disappear_from_audit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "LICENSE.md").write_bytes((ROOT / "LICENSE.md").read_bytes())
            (root / "bad.rs").write_bytes(b"\xff")
            with patch("subprocess.check_output", return_value="bad.rs\n"):
                with self.assertRaises(UnicodeError):
                    self.checker(root)()


if __name__ == "__main__":
    unittest.main()
