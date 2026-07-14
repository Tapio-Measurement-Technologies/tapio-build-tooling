from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import load_config
from tapio_build_tools.ecosystems.python.sbom import (
    SbomError,
    connect_root_dependencies,
    generate_sbom,
    sha256_file,
)


class SbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "requirements.in").write_text("Example_Package==1\n", encoding="utf-8")
        (self.root / "requirements.txt").write_text("example-package==1\n", encoding="utf-8")
        (self.root / "build-tooling.toml").write_text(
            """schema-version = 1
[organization]
name = "Tapio"
website = "https://example.com"
[products.demo]
name = "Demo"
license-id = "GPL-3.0-or-later"
repository = "https://example.com/demo"
[ecosystems.python]
version = "3.12"
[[ecosystems.python.requirements]]
name = "runtime"
input = "requirements.in"
lock = "requirements.txt"
""",
            encoding="utf-8",
        )
        self.config = load_config(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def fake_cyclonedx(lock, output, spec_version, project) -> None:
        output.write_text(
            json.dumps(
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": spec_version,
                    "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
                    "version": 1,
                    "metadata": {},
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "pkg:pypi/example-package@1",
                            "name": "example-package",
                            "version": "1",
                            "purl": "pkg:pypi/example-package@1",
                        }
                    ],
                    "dependencies": [{"ref": "pkg:pypi/example-package@1"}],
                }
            ),
            encoding="utf-8",
        )

    @patch("tapio_build_tools.ecosystems.python.sbom.validate_json")
    @patch("tapio_build_tools.ecosystems.python.sbom._run_cyclonedx")
    def test_generates_source_sbom_without_artifact_metadata(self, run, validate) -> None:
        run.side_effect = self.fake_cyclonedx
        output = generate_sbom(
            self.config,
            group_name="runtime",
            product_id="demo",
            output="demo.cdx.json",
            version="1.2.3",
            commit_sha="abc",
            build_platform="linux",
        )
        bom = json.loads(output.read_text())
        root = bom["metadata"]["component"]
        self.assertEqual(root["name"], "Demo")
        self.assertNotIn("hashes", root)
        self.assertEqual(bom["dependencies"][-1]["dependsOn"], ["pkg:pypi/example-package@1"])
        validate.assert_called_once()

    @patch("tapio_build_tools.ecosystems.python.sbom.validate_json")
    @patch("tapio_build_tools.ecosystems.python.sbom._run_cyclonedx")
    def test_artifact_sbom_hashes_file_and_adds_embedded_parts(self, run, validate) -> None:
        run.side_effect = self.fake_cyclonedx
        artifact = self.root / "demo.exe"
        artifact.write_bytes(b"artifact")
        output = generate_sbom(
            self.config,
            group_name="runtime",
            product_id="demo",
            output="artifact.cdx.json",
            version="1.2.3",
            artifact=artifact,
            artifact_kind="pyinstaller",
            pyinstaller_version="6.19.0",
        )
        bom = json.loads(output.read_text())
        self.assertEqual(bom["metadata"]["component"]["hashes"][0]["content"], sha256_file(artifact))
        names = {component["name"] for component in bom["components"]}
        self.assertIn("Python", names)
        self.assertIn("PyInstaller bootloader", names)

    def test_lock_only_graph_treats_all_components_as_roots(self) -> None:
        bom = {
            "components": [
                {"bom-ref": "a", "name": "a"},
                {"bom-ref": "b", "name": "b"},
            ]
        }
        connect_root_dependencies(bom, "root", None)
        self.assertEqual(bom["dependencies"][0]["dependsOn"], ["a", "b"])

    def test_requires_artifact_kind_with_artifact(self) -> None:
        artifact = self.root / "demo.exe"
        artifact.write_bytes(b"artifact")
        with self.assertRaisesRegex(SbomError, "must be supplied together"):
            generate_sbom(
                self.config,
                group_name="runtime",
                product_id="demo",
                output="bad.cdx.json",
                version="1",
                artifact=artifact,
            )


if __name__ == "__main__":
    unittest.main()

