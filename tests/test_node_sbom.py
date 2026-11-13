import base64
import copy
import hashlib
from pathlib import Path
import json
import shutil
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


def _digest(name: str, version: str) -> bytes:
    return hashlib.sha512(f"{name}-{version}.tgz".encode()).digest()


def _locked(name: str, version: str, **extra) -> dict:
    return {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        "integrity": "sha512-" + base64.b64encode(_digest(name, version)).decode(),
        **extra,
    }


# c@2.0.0 and e@2.0.0 hold the top-level slots, so c@1.0.0 and e@1.0.0 are
# each installed twice: under the development dependency a, and under the
# production dependency b. npm cannot dedupe them. c@1.0.0's own dependency d
# resolves to a's nested d@1.0.0 at one path and to the hoisted d@1.1.0 at the
# other; e@1.0.0 depends on nothing, so npm 10 writes two identical dependency
# entries for it.
NESTED_PACKAGE = {
    "name": "demo",
    "version": "0.0.0",
    "private": True,
    "dependencies": {"b": "1.0.0", "c": "2.0.0", "e": "2.0.0"},
    "devDependencies": {"a": "1.0.0"},
}
NESTED_LOCK = {
    "name": "demo",
    "version": "0.0.0",
    "lockfileVersion": 3,
    "requires": True,
    "packages": {
        "": {
            "name": "demo",
            "version": "0.0.0",
            "dependencies": {"b": "1.0.0", "c": "2.0.0", "e": "2.0.0"},
            "devDependencies": {"a": "1.0.0"},
        },
        "node_modules/a": _locked(
            "a", "1.0.0", dev=True, dependencies={"c": "1.0.0", "e": "1.0.0"}
        ),
        "node_modules/a/node_modules/c": _locked(
            "c", "1.0.0", dev=True, dependencies={"d": "^1.0.0"}
        ),
        "node_modules/a/node_modules/d": _locked("d", "1.0.0", dev=True),
        "node_modules/a/node_modules/e": _locked("e", "1.0.0", dev=True),
        "node_modules/b": _locked("b", "1.0.0", dependencies={"c": "1.0.0", "e": "1.0.0"}),
        "node_modules/b/node_modules/c": _locked("c", "1.0.0", dependencies={"d": "^1.0.0"}),
        "node_modules/b/node_modules/e": _locked("e", "1.0.0"),
        "node_modules/c": _locked("c", "2.0.0"),
        "node_modules/d": _locked("d", "1.1.0"),
        "node_modules/e": _locked("e", "2.0.0"),
    },
}


def _npm10_component(ref: str, path: str, *, development: bool = False) -> dict:
    name, version = ref.rsplit("@", 1)
    properties = [{"name": "cdx:npm:package:path", "value": path}]
    if development:
        properties.append({"name": "cdx:npm:package:development", "value": "true"})
    return {
        "bom-ref": ref,
        "type": "library",
        "name": name,
        "version": version,
        "scope": "optional" if development else "required",
        "purl": f"pkg:npm/{ref}",
        "properties": properties,
        "externalReferences": [
            {
                "type": "distribution",
                "url": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            }
        ],
        "hashes": [{"alg": "SHA-512", "content": _digest(name, version).hex()}],
    }


def npm10_nested_bom() -> dict:
    """What npm 10 writes for NESTED_LOCK: a component and a dependency entry per install path."""
    bom = npm_bom()
    bom["components"] = [
        _npm10_component("a@1.0.0", "node_modules/a", development=True),
        _npm10_component("c@1.0.0", "node_modules/a/node_modules/c", development=True),
        _npm10_component("d@1.0.0", "node_modules/a/node_modules/d", development=True),
        _npm10_component("e@1.0.0", "node_modules/a/node_modules/e", development=True),
        _npm10_component("b@1.0.0", "node_modules/b"),
        _npm10_component("c@1.0.0", "node_modules/b/node_modules/c"),
        _npm10_component("e@1.0.0", "node_modules/b/node_modules/e"),
        _npm10_component("c@2.0.0", "node_modules/c"),
        _npm10_component("d@1.1.0", "node_modules/d"),
        _npm10_component("e@2.0.0", "node_modules/e"),
    ]
    bom["dependencies"] = [
        {"ref": "demo@0.0.0", "dependsOn": ["b@1.0.0", "c@2.0.0", "e@2.0.0", "a@1.0.0"]},
        {"ref": "a@1.0.0", "dependsOn": ["c@1.0.0", "e@1.0.0"]},
        {"ref": "c@1.0.0", "dependsOn": ["d@1.0.0"]},
        {"ref": "d@1.0.0", "dependsOn": []},
        {"ref": "e@1.0.0", "dependsOn": []},
        {"ref": "b@1.0.0", "dependsOn": ["c@1.0.0", "e@1.0.0"]},
        {"ref": "c@1.0.0", "dependsOn": ["d@1.1.0"]},
        {"ref": "e@1.0.0", "dependsOn": []},
        {"ref": "c@2.0.0", "dependsOn": []},
        {"ref": "d@1.1.0", "dependsOn": []},
        {"ref": "e@2.0.0", "dependsOn": []},
    ]
    return bom


def _npm11_component(ref: str, *, development: bool = False) -> dict:
    component = _npm10_component(ref, "", development=development)
    component["properties"] = [
        item for item in component["properties"] if item["name"] != "cdx:npm:package:path"
    ]
    return component


def npm11_nested_bom() -> dict:
    """What npm 11 writes for NESTED_LOCK: each version once, as its first install path has it.

    The copies of c@1.0.0 and e@1.0.0 under the development dependency a come
    first, so both are optional and development, and c@1.0.0 depends only on
    the d@1.0.0 nested beside it under a.
    """
    bom = npm_bom()
    bom["components"] = [
        _npm11_component("a@1.0.0", development=True),
        _npm11_component("c@1.0.0", development=True),
        _npm11_component("d@1.0.0", development=True),
        _npm11_component("e@1.0.0", development=True),
        _npm11_component("b@1.0.0"),
        _npm11_component("c@2.0.0"),
        _npm11_component("d@1.1.0"),
        _npm11_component("e@2.0.0"),
    ]
    bom["dependencies"] = [
        {"ref": "demo@0.0.0", "dependsOn": ["b@1.0.0", "c@2.0.0", "e@2.0.0", "a@1.0.0"]},
        {"ref": "a@1.0.0", "dependsOn": ["c@1.0.0", "e@1.0.0"]},
        {"ref": "c@1.0.0", "dependsOn": ["d@1.0.0"]},
        {"ref": "d@1.0.0", "dependsOn": []},
        {"ref": "e@1.0.0", "dependsOn": []},
        {"ref": "b@1.0.0", "dependsOn": ["c@1.0.0", "e@1.0.0"]},
        {"ref": "c@2.0.0", "dependsOn": []},
        {"ref": "d@1.1.0", "dependsOn": []},
        {"ref": "e@2.0.0", "dependsOn": []},
    ]
    return bom


def nested_lock(**changes: dict) -> dict:
    """NESTED_LOCK with the entries at the given install paths replaced."""
    lock = copy.deepcopy(NESTED_LOCK)
    lock["packages"].update(changes)
    return lock


def _without_paths(components: list[dict]) -> list[dict]:
    return [
        {
            **component,
            "properties": [
                item
                for item in component.get("properties") or []
                if item["name"] != "cdx:npm:package:path"
            ],
        }
        for component in components
    ]


class NodeSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
        (self.root / "package-lock.json").write_text(
            '{"name":"demo","lockfileVersion":3,"packages":{}}\n', encoding="utf-8"
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

    def _generate(self, npm_output: dict, lock: dict = NESTED_LOCK) -> dict:
        (self.root / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
        with patch("tapio_build_tools.ecosystems.node.sbom.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(npm_output)
            )
            output = generate_sbom(
                self.config,
                product_id="demo",
                output="demo.cdx.json",
                version="1.2.3",
                commit_sha="abc",
                build_platform="linux",
                build_timestamp="2026-07-16T00:00:00Z",
            )
        return json.loads(output.read_text())

    def test_lists_a_version_installed_at_several_paths_once(self) -> None:
        bom = self._generate(npm10_nested_bom())

        self.assertEqual(
            [item["bom-ref"] for item in bom["components"]],
            [
                "a@1.0.0",
                "c@1.0.0",
                "d@1.0.0",
                "e@1.0.0",
                "b@1.0.0",
                "c@2.0.0",
                "d@1.1.0",
                "e@2.0.0",
            ],
        )
        nested = next(item for item in bom["components"] if item["bom-ref"] == "c@1.0.0")
        # b needs it in production, so it is not a development dependency
        # even though the copy under a, listed first, is one.
        self.assertEqual(nested["scope"], "required")
        self.assertEqual(
            nested["properties"],
            [
                {"name": "cdx:npm:package:path", "value": "node_modules/a/node_modules/c"},
                {"name": "cdx:npm:package:path", "value": "node_modules/b/node_modules/c"},
            ],
        )
        graph = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
        self.assertEqual(len(graph), len(bom["dependencies"]))
        self.assertEqual(graph["c@1.0.0"], ["d@1.0.0", "d@1.1.0"])
        self.assertEqual(graph["e@1.0.0"], [])
        self.assertEqual(graph["a@1.0.0"], ["c@1.0.0", "e@1.0.0"])
        self.assertEqual(graph["b@1.0.0"], ["c@1.0.0", "e@1.0.0"])
        root = bom["metadata"]["component"]["bom-ref"]
        self.assertEqual(graph[root], ["a@1.0.0", "b@1.0.0", "c@2.0.0", "e@2.0.0"])

    def test_keeps_development_when_every_copy_is_development(self) -> None:
        npm_output = npm10_nested_bom()
        npm_output["components"][5] = _npm10_component(
            "c@1.0.0", "node_modules/b/node_modules/c", development=True
        )
        lock = nested_lock(
            **{
                "node_modules/b/node_modules/c": _locked(
                    "c", "1.0.0", dev=True, dependencies={"d": "^1.0.0"}
                )
            }
        )

        bom = self._generate(npm_output, lock)

        nested = next(item for item in bom["components"] if item["bom-ref"] == "c@1.0.0")
        self.assertEqual(nested["scope"], "optional")
        self.assertIn(
            {"name": "cdx:npm:package:development", "value": "true"}, nested["properties"]
        )

    def test_rejects_copies_of_a_version_that_differ(self) -> None:
        npm_output = npm10_nested_bom()
        npm_output["components"][5]["hashes"] = [{"alg": "SHA-512", "content": "0" * 128}]
        with self.assertRaisesRegex(SbomError, "c@1.0.0"):
            self._generate(npm_output)

    def test_reads_the_scope_and_edges_npm_11_drops_from_the_lock(self) -> None:
        bom = self._generate(npm11_nested_bom())

        components = {item["bom-ref"]: item for item in bom["components"]}
        # b needs both in production, though npm 11 kept the copies under
        # the development dependency a.
        for ref in ("c@1.0.0", "e@1.0.0"):
            self.assertEqual(components[ref]["scope"], "required")
            self.assertEqual(components[ref]["properties"], [])
        graph = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
        self.assertEqual(len(graph), len(bom["dependencies"]))
        # Under a, d resolves to a's own nested d@1.0.0; under b, which has
        # no d, to the top-level d@1.1.0.
        self.assertEqual(graph["c@1.0.0"], ["d@1.0.0", "d@1.1.0"])

        # Everything else is as npm 11 wrote it, in its order.
        npm_output = npm11_nested_bom()
        self.assertEqual(list(components), [item["bom-ref"] for item in npm_output["components"]])
        for component in npm_output["components"]:
            if component["bom-ref"] not in ("c@1.0.0", "e@1.0.0"):
                self.assertEqual(components[component["bom-ref"]], component)
        for entry in npm_output["dependencies"][1:]:
            if entry["ref"] != "c@1.0.0":
                self.assertEqual(graph[entry["ref"]], entry["dependsOn"])

    def test_npm_10_and_npm_11_give_the_same_bom(self) -> None:
        npm10 = self._generate(npm10_nested_bom())
        npm11 = self._generate(npm11_nested_bom())

        # npm 11 no longer writes install paths; nothing else differs.
        self.assertEqual(_without_paths(npm10["components"]), npm11["components"])
        self.assertEqual(npm10["dependencies"], npm11["dependencies"])

    def test_keeps_npm_11_development_when_every_install_path_is_development(self) -> None:
        lock = nested_lock(
            **{
                "node_modules/b/node_modules/c": _locked(
                    "c", "1.0.0", dev=True, dependencies={"d": "^1.0.0"}
                )
            }
        )

        bom = self._generate(npm11_nested_bom(), lock)

        nested = next(item for item in bom["components"] if item["bom-ref"] == "c@1.0.0")
        self.assertEqual(nested, _npm11_component("c@1.0.0", development=True))

    def test_drops_npm_11_development_for_an_optional_production_path(self) -> None:
        lock = nested_lock(
            **{
                "node_modules/b/node_modules/c": _locked(
                    "c", "1.0.0", optional=True, dependencies={"d": "^1.0.0"}
                )
            }
        )

        bom = self._generate(npm11_nested_bom(), lock)

        nested = next(item for item in bom["components"] if item["bom-ref"] == "c@1.0.0")
        self.assertEqual(nested["scope"], "optional")
        self.assertEqual(nested["properties"], [])

    def test_resolves_an_edge_through_a_workspace_link(self) -> None:
        # Only b's copy of c@1.0.0 depends on the workspace w, which npm
        # installs as a link to its directory.
        lock = nested_lock(
            **{
                "node_modules/b/node_modules/c": _locked(
                    "c", "1.0.0", dependencies={"d": "^1.0.0", "w": "*"}
                ),
                "node_modules/w": {"resolved": "packages/w", "link": True},
                "packages/w": {"name": "w", "version": "1.0.0"},
            }
        )
        npm_output = npm11_nested_bom()
        npm_output["components"].append(
            {
                "bom-ref": "w@1.0.0",
                "type": "library",
                "name": "w",
                "version": "1.0.0",
                "scope": "required",
                "purl": "pkg:npm/w@1.0.0",
                "properties": [],
            }
        )
        npm_output["dependencies"].append({"ref": "w@1.0.0", "dependsOn": []})

        bom = self._generate(npm_output, lock)

        graph = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
        self.assertEqual(graph["c@1.0.0"], ["d@1.0.0", "d@1.1.0", "w@1.0.0"])

    def test_ignores_an_edge_to_a_package_npm_does_not_list(self) -> None:
        lock = nested_lock(
            **{
                "node_modules/b/node_modules/c": _locked(
                    "c", "1.0.0", dependencies={"d": "^1.0.0"}, peerDependencies={"p": "*"}
                ),
                "node_modules/p": _locked("p", "1.0.0"),
            }
        )

        bom = self._generate(npm11_nested_bom(), lock)

        graph = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
        self.assertEqual(graph["c@1.0.0"], ["d@1.0.0", "d@1.1.0"])

    def test_rejects_a_lock_without_a_packages_table(self) -> None:
        with self.assertRaisesRegex(SbomError, "lockfileVersion 2 or 3"):
            self._generate(npm11_nested_bom(), {"lockfileVersion": 1, "dependencies": {}})

    @unittest.skipIf(shutil.which("npm") is None, "npm is not installed")
    def test_npm_sbom_of_a_lock_with_nested_copies_validates(self) -> None:
        (self.root / "package.json").write_text(json.dumps(NESTED_PACKAGE), encoding="utf-8")
        (self.root / "package-lock.json").write_text(json.dumps(NESTED_LOCK), encoding="utf-8")
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
        refs = [item["bom-ref"] for item in bom["components"]]
        self.assertEqual(len(refs), len(set(refs)))
        self.assertEqual(
            set(refs),
            {
                "a@1.0.0",
                "b@1.0.0",
                "c@1.0.0",
                "c@2.0.0",
                "d@1.0.0",
                "d@1.1.0",
                "e@1.0.0",
                "e@2.0.0",
            },
        )
        components = {item["bom-ref"]: item for item in bom["components"]}
        development = {"name": "cdx:npm:package:development", "value": "true"}
        # Whichever npm wrote it, a version b needs is required and not
        # development, and one only a needs stays development.
        for ref in ("c@1.0.0", "e@1.0.0"):
            self.assertEqual(components[ref]["scope"], "required")
            self.assertNotIn(development, components[ref].get("properties") or [])
        for ref in ("a@1.0.0", "d@1.0.0"):
            self.assertEqual(components[ref]["scope"], "optional")
            self.assertIn(development, components[ref]["properties"])
        graph = {item["ref"]: item["dependsOn"] for item in bom["dependencies"]}
        self.assertEqual(len(graph), len(bom["dependencies"]))
        self.assertEqual(graph["a@1.0.0"], ["c@1.0.0", "e@1.0.0"])
        self.assertEqual(graph["b@1.0.0"], ["c@1.0.0", "e@1.0.0"])
        self.assertEqual(graph["c@1.0.0"], ["d@1.0.0", "d@1.1.0"])
        root = bom["metadata"]["component"]["bom-ref"]
        self.assertEqual(graph[root], ["a@1.0.0", "b@1.0.0", "c@2.0.0", "e@2.0.0"])


if __name__ == "__main__":
    unittest.main()
