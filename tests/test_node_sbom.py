from pathlib import Path
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import load_config
from tapio_build_tools.ecosystems.node.sbom import SbomError, generate_sbom


CONFIG = """schema-version = 1
[organization]
name = "Tapio"
website = "https://example.com"
[products.demo]
name = "Demo App"
license-name = "Proprietary"
repository = "https://example.com/demo"
[ecosystems.node]
version = "24"
package = "package.json"
lock = "package-lock.json"
"""


def npm_bom() -> dict:
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "version": 1,
        "metadata": {
            "timestamp": "2020-01-01T00:00:00.000Z",
            "component": {
                "type": "application",
                "bom-ref": "demo@0.0.0",
                "name": "demo",
                "version": "0.0.0",
                "properties": [{"name": "cdx:npm:package:private", "value": "true"}],
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "qrcode@1.5.4",
                "name": "qrcode",
                "version": "1.5.4",
                "scope": "required",
                "purl": "pkg:npm/qrcode@1.5.4",
            },
            {
                "type": "library",
                "bom-ref": "vite@6.4.3",
                "name": "vite",
                "version": "6.4.3",
                "scope": "optional",
                "purl": "pkg:npm/vite@6.4.3",
                "properties": [{"name": "cdx:npm:package:development", "value": "true"}],
            },
        ],
        "dependencies": [
            {"ref": "qrcode@1.5.4"},
            {"ref": "vite@6.4.3"},
            {"ref": "demo@0.0.0", "dependsOn": ["vite@6.4.3", "qrcode@1.5.4"]},
        ],
    }


class NodeSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (self.root / "package-lock.json").write_text(
            '{"name":"demo","lockfileVersion":3}\n', encoding="utf-8"
        )
        (self.root / "build-tooling.toml").write_text(CONFIG, encoding="utf-8")
        self.config = load_config(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @patch("tapio_build_tools.ecosystems.node.sbom.validate_json")
    @patch("tapio_build_tools.ecosystems.node.sbom.subprocess.run")
    def test_generates_stamped_cyclonedx_with_remapped_root(self, run, validate) -> None:
        run.return_value = subprocess.CompletedProcess([], 0, stdout=json.dumps(npm_bom()))
        output = generate_sbom(
            self.config,
            product_id="demo",
            output="demo.cdx.json",
            version="1.2.3",
            commit_sha="abc",
            build_platform="linux",
            build_timestamp="2026-07-16T00:00:00Z",
        )
        bom = json.loads(output.read_text())
        root = bom["metadata"]["component"]
        self.assertEqual(root["name"], "Demo App")
        self.assertEqual(root["version"], "1.2.3")
        self.assertEqual(root["publisher"], "Tapio")
        self.assertEqual(root["licenses"], [{"license": {"name": "Proprietary"}}])
        root_graph = next(item for item in bom["dependencies"] if item["ref"] == root["bom-ref"])
        self.assertEqual(root_graph["dependsOn"], ["qrcode@1.5.4", "vite@6.4.3"])
        self.assertFalse(any(item["ref"] == "demo@0.0.0" for item in bom["dependencies"]))
        metadata_properties = {
            item["name"]: item["value"] for item in bom["metadata"]["properties"]
        }
        self.assertEqual(metadata_properties["tapio:sbom:commit-sha"], "abc")
        self.assertEqual(metadata_properties["tapio:sbom:lock-file"], "package-lock.json")
        self.assertEqual(bom["specVersion"], "1.5")
        validate.assert_called_once()
        command = run.call_args.args[0]
        self.assertIn("--package-lock-only", command)
        self.assertIn("cyclonedx", command)

    @patch("tapio_build_tools.ecosystems.node.sbom.subprocess.run")
    def test_malformed_npm_output_preserves_existing_output(self, run) -> None:
        output = self.root / "demo.cdx.json"
        output.write_text("existing\n", encoding="utf-8")
        run.return_value = subprocess.CompletedProcess([], 0, stdout="not json")
        with self.assertRaisesRegex(SbomError, "invalid JSON"):
            generate_sbom(
                self.config,
                product_id="demo",
                output=output,
                version="1",
            )
        self.assertEqual(output.read_text(), "existing\n")

    @patch("tapio_build_tools.ecosystems.node.sbom.subprocess.run")
    def test_rejects_missing_root_graph(self, run) -> None:
        bom = npm_bom()
        bom["dependencies"] = bom["dependencies"][:-1]
        run.return_value = subprocess.CompletedProcess([], 0, stdout=json.dumps(bom))
        with self.assertRaisesRegex(SbomError, "root dependency graph"):
            generate_sbom(
                self.config,
                product_id="demo",
                output="bad.cdx.json",
                version="1",
            )


if __name__ == "__main__":
    unittest.main()
