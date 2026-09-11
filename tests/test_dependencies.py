import json
import tempfile
import unittest
from pathlib import Path

from whitehat.dependencies import (
    DependencyError,
    DependencyLimitError,
    DependencyLimits,
    compare_dependency_manifests,
    load_dependency_manifest,
)


ROOT = Path(__file__).resolve().parents[1]


class DependencyTests(unittest.TestCase):
    def test_compares_python_declared_dependencies(self) -> None:
        result = compare_dependency_manifests(
            ROOT / "examples" / "dependencies" / "before" / "pyproject.toml",
            ROOT / "examples" / "dependencies" / "after" / "pyproject.toml",
        )
        self.assertEqual(result["ecosystem"], "python")
        self.assertEqual(
            result["summary"],
            {"added": 1, "removed": 1, "changed": 1, "unchanged": 1},
        )
        self.assertEqual(
            [(change["kind"], change["key"]) for change in result["changes"]],
            [
                ("removed", "main:pydantic"),
                ("changed", "main:requests"),
                ("added", "main:rich"),
            ],
        )

    def test_accepts_multiple_python_markers_for_one_package(self) -> None:
        content = """[project]
name = "sample"
version = "1"
dependencies = [
  "typing-extensions>=4; python_version < '3.12'",
  "typing_extensions>=4.10; python_version >= '3.12'",
]
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "pyproject.toml")
            path.write_text(content, encoding="utf-8")
            manifest = load_dependency_manifest(path)
        record = manifest.records["main:typing-extensions"]
        self.assertEqual(len(record["requirements"]), 2)

    def test_compares_npm_v3_resolved_packages(self) -> None:
        before = {
            "name": "sample",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "^1.0.0"}},
                "node_modules/alpha": {
                    "version": "1.0.0",
                    "integrity": "sha512-A",
                    "resolved": "https://private.invalid/token/alpha.tgz",
                },
                "node_modules/alpha/node_modules/beta": {"version": "2.0.0"},
            },
        }
        after = {
            "name": "sample",
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"alpha": "^2.0.0", "gamma": "1.0.0"}},
                "node_modules/alpha": {"version": "2.0.0", "integrity": "sha512-B"},
                "node_modules/alpha/node_modules/beta": {"version": "2.0.0"},
                "node_modules/gamma": {"version": "1.0.0"},
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            before_path = Path(temporary, "before.json")
            after_path = Path(temporary, "after.json")
            before_path.write_text(json.dumps(before), encoding="utf-8")
            after_path.write_text(json.dumps(after), encoding="utf-8")
            result = compare_dependency_manifests(before_path, after_path)

        self.assertEqual(result["ecosystem"], "npm")
        self.assertEqual(
            result["summary"],
            {"added": 1, "removed": 0, "changed": 1, "unchanged": 1},
        )
        changed = next(
            change for change in result["changes"] if change["kind"] == "changed"
        )
        self.assertTrue(changed["after"]["direct"])
        self.assertEqual(changed["after"]["scope"], "runtime")
        self.assertEqual(changed["after"]["requested"], "^2.0.0")
        self.assertNotIn("private.invalid", json.dumps(result))

    def test_detects_npm_requested_range_change_without_resolution_change(self) -> None:
        def lock(requested: str) -> dict[str, object]:
            return {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"alpha": requested}},
                    "node_modules/alpha": {"version": "1.5.0"},
                },
            }

        with tempfile.TemporaryDirectory() as temporary:
            before_path = Path(temporary, "before.json")
            after_path = Path(temporary, "after.json")
            before_path.write_text(json.dumps(lock("^1.0.0")), encoding="utf-8")
            after_path.write_text(json.dumps(lock("^1.5.0")), encoding="utf-8")
            result = compare_dependency_manifests(before_path, after_path)
        self.assertEqual(
            result["summary"],
            {"added": 0, "removed": 0, "changed": 1, "unchanged": 0},
        )

    def test_loads_nested_npm_v1_dependencies(self) -> None:
        value = {
            "lockfileVersion": 1,
            "dependencies": {
                "alpha": {
                    "version": "1.0.0",
                    "dependencies": {"beta": {"version": "2.0.0"}},
                }
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "package-lock.json")
            path.write_text(json.dumps(value), encoding="utf-8")
            manifest = load_dependency_manifest(path)
        self.assertEqual(
            sorted(manifest.records),
            ["node_modules/alpha", "node_modules/alpha/node_modules/beta"],
        )

    def test_rejects_dynamic_python_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "pyproject.toml")
            path.write_text(
                '[project]\nname="sample"\nversion="1"\ndynamic=["dependencies"]\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DependencyError, "dynamic"):
                load_dependency_manifest(path)

    def test_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary, "package-lock.json")
            path.write_text(
                '{"lockfileVersion":3,"lockfileVersion":2,"packages":{}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(DependencyError, "duplicate JSON key"):
                load_dependency_manifest(path)

    def test_rejects_ecosystem_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            package_lock = Path(temporary, "package-lock.json")
            package_lock.write_text(
                '{"lockfileVersion":3,"packages":{"":{}}}', encoding="utf-8"
            )
            with self.assertRaisesRegex(DependencyError, "same ecosystem"):
                compare_dependency_manifests(
                    ROOT / "examples" / "dependencies" / "before" / "pyproject.toml",
                    package_lock,
                )

    def test_enforces_dependency_limit(self) -> None:
        limits = DependencyLimits(max_manifest_bytes=10_000, max_dependencies=1)
        with self.assertRaisesRegex(DependencyLimitError, "dependency count"):
            load_dependency_manifest(
                ROOT / "examples" / "dependencies" / "before" / "pyproject.toml",
                limits,
            )


if __name__ == "__main__":
    unittest.main()
