from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).parents[1]


class ActionTests(unittest.TestCase):
    def test_external_actions_use_full_commit_shas(self) -> None:
        files = [
            ROOT / ".github/workflows/ci.yml",
            ROOT / ".github/workflows/supply-chain.yml",
            ROOT / "actions/python-supply-chain/action.yml",
            ROOT / "actions/python-release-checks/action.yml",
            ROOT / "actions/python-release-evidence/action.yml",
            ROOT / "actions/node-supply-chain/action.yml",
            ROOT / "actions/publish-downloads/action.yml",
            ROOT / "actions/publish-release-notes/action.yml",
            ROOT / "actions/builder-image/action.yml",
            ROOT / "actions/publish-archive/action.yml",
            ROOT / "actions/sign-module/action.yml",
        ]
        uses = []
        for path in files:
            uses.extend(re.findall(r"uses:\s+([^\s]+)", path.read_text(encoding="utf-8")))
        self.assertTrue(uses)
        for value in uses:
            with self.subTest(value=value):
                if value.startswith("./"):
                    continue
                self.assertRegex(value, r"^[^@]+@[0-9a-f]{40}$")

    def test_ci_has_least_privilege_permissions(self) -> None:
        for name in ["ci.yml", "supply-chain.yml"]:
            with self.subTest(workflow=name):
                workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                self.assertIn("permissions:\n  contents: read", workflow)
                self.assertIn("persist-credentials: false", workflow)

    def test_tooling_lock_includes_no_isolation_build_requirements(self) -> None:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        build_requirements = set(pyproject["build-system"]["requires"])
        lock_inputs = {
            line
            for raw_line in (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines()
            if (line := raw_line.strip()) and not line.startswith(("#", "--"))
        }
        self.assertLessEqual(build_requirements, lock_inputs)

    def test_release_checks_validate_before_auditing(self) -> None:
        action = (ROOT / "actions/python-release-checks" / "action.yml").read_text(
            encoding="utf-8"
        )
        self.assertLess(action.index("config validate"), action.index("compile --check"))
        self.assertLess(action.index("compile --check"), action.index("python cooldown"))
        self.assertLess(action.index("python cooldown"), action.index("python audit"))

    def test_supply_chain_actions_check_release_ages(self) -> None:
        for name in ["python-supply-chain", "node-supply-chain", "python-release-checks"]:
            with self.subTest(action=name):
                action = (ROOT / "actions" / name / "action.yml").read_text(encoding="utf-8")
                self.assertIn("cooldown:", action)
                self.assertIn("inputs.cooldown == 'true'", action)

    def test_release_checks_leave_python_to_the_calling_workflow(self) -> None:
        action = (ROOT / "actions/python-release-checks" / "action.yml").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("setup-python", action)

    def test_node_action_validates_before_generating_and_auditing(self) -> None:
        action = (ROOT / "actions/node-supply-chain" / "action.yml").read_text(encoding="utf-8")
        self.assertLess(action.index("npm ci"), action.index("node sbom"))
        self.assertLess(action.index("node sbom"), action.index("node audit"))
        self.assertIn("--ignore-scripts --no-audit --no-fund", action)

    def test_publish_downloads_validates_and_authenticates_before_publishing(self) -> None:
        action = (ROOT / "actions/publish-downloads" / "action.yml").read_text(encoding="utf-8")
        self.assertLess(action.index("config validate"), action.index("configure-aws-credentials"))
        self.assertLess(action.index("configure-aws-credentials"), action.index("downloads publish"))
        self.assertNotIn("--acl", action)

    def test_publish_archive_validates_and_authenticates_before_publishing(self) -> None:
        action = (ROOT / "actions/publish-archive" / "action.yml").read_text(encoding="utf-8")
        self.assertLess(action.index("config validate"), action.index("configure-aws-credentials"))
        self.assertLess(action.index("configure-aws-credentials"), action.index("archive publish"))
        self.assertIn("inputs.bucket != ''", action)
        self.assertNotIn("--acl", action)

    def test_builder_image_is_named_by_the_tooling_before_it_is_built(self) -> None:
        action = (ROOT / "actions/builder-image" / "action.yml").read_text(encoding="utf-8")
        self.assertLess(action.index("config validate"), action.index("archive names"))
        self.assertLess(action.index("archive names"), action.index("docker build"))
        self.assertNotIn("configure-aws-credentials", action)

    def test_sign_module_signs_only_through_the_tooling(self) -> None:
        """Login, then one command that signs, verifies and records - nothing else."""
        action = (ROOT / "actions/sign-module" / "action.yml").read_text(encoding="utf-8")
        self.assertLess(action.index("azure/login"), action.index("tapio-build signing sign"))
        self.assertNotIn("az keyvault", action)
        self.assertIn("--summary \"$GITHUB_STEP_SUMMARY\"", action)

    def test_signing_code_carries_no_deployment_of_its_own(self) -> None:
        for path in (ROOT / "src/tapio_build_tools/signing").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            for literal in ["vault.azure.net", "tapiotechnologies", "Tapio-Measurement-Technologies"]:
                with self.subTest(file=path.name, literal=literal):
                    self.assertNotIn(literal, text)
            self.assertIsNone(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text),
                              f"a GUID in {path.name}")

    def test_publish_downloads_carries_no_deployment_of_its_own(self) -> None:
        """The tooling is public; buckets, roles and addresses belong to the consumer."""
        for name in ["publish-downloads", "publish-release-notes", "publish-archive", "builder-image",
                     "sign-module"]:
            action = (ROOT / "actions" / name / "action.yml").read_text(encoding="utf-8")
            for literal in ["arn:aws:", "amazonaws.com", "s3://", "tapiotechnologies",
                            "vault.azure.net", "/subscriptions/"]:
                with self.subTest(action=name, literal=literal):
                    self.assertNotIn(literal, action)
            self.assertIsNone(re.search(r"[\w.-]+@[\w-]+\.\w+", action), f"an email address in {name}")


if __name__ == "__main__":
    unittest.main()
