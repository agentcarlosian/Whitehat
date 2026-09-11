import tomllib
import unittest
from pathlib import Path

from whitehat import __version__


class VersionTests(unittest.TestCase):
    def test_package_and_distribution_versions_match(self) -> None:
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        self.assertEqual(metadata["project"]["version"], __version__)


if __name__ == "__main__":
    unittest.main()
