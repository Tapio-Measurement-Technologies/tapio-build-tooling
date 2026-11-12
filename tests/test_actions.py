from pathlib import Path
import re
import tomllib
import unittest


ROOT = Path(__file__).parents[1]
SIGNING_LIBRARY = ROOT / "packages/tapio-module-signing"
UPDATE_CHECK_LIBRARY = ROOT / "packages/tapio-update-check"
# Each library products install, with the tag prefix it is released from and
# all it may depend on: products bundle it, so whatever it pulls in, every
# product ships.
LIBRARIES = {
    SIGNING_LIBRARY: ("module-signing-v", ["cryptography"]),
    UPDATE_CHECK_LIBRARY: ("update-check-v", ["packaging"]),
}
RELEASE_WORKFLOW = ROOT / ".github/workflows/release-library.yml"


def pins(lock: Path) -> dict[str, str]:
    """The name==version lines of a compiled lock."""
    found = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^([A-Za-z0-9._-]+)==([^\s;]+)", line)
        if match:
            found[match.group(1).lower()] = match.group(2)
    return found


class ActionTests(unittest.TestCase):
    def test_external_actions_use_full_commit_shas(self) -> None:
        files = sorted([*ROOT.glob(".github/workflows/*.yml"), *ROOT.glob("actions/*/action.yml")])
        self.assertGreaterEqual(len(files), 13)
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
        for name in ["ci.yml", "supply-chain.yml", "container-supply-chain.yml"]:
            with self.subTest(workflow=name):
                workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
                self.assertIn("permissions:\n  contents: read", workflow)
                self.assertIn("persist-credentials: false", workflow)

    def test_tooling_lock_includes_no_isolation_build_requirements(self) -> None:
        """Both packages are built with --no-build-isolation from the tooling lock."""
        lock_inputs = {
            line
            for raw_line in (ROOT / "requirements.in").read_text(encoding="utf-8").splitlines()
            if (line := raw_line.strip()) and not line.startswith(("#", "--"))
        }
        for path in [ROOT / "pyproject.toml", *(library / "pyproject.toml" for library in LIBRARIES)]:
            with self.subTest(pyproject=str(path.relative_to(ROOT))):
                pyproject = tomllib.loads(path.read_text(encoding="utf-8"))
                self.assertLessEqual(set(pyproject["build-system"]["requires"]), lock_inputs)

    def test_the_library_release_builds_from_main_and_writes_only_to_publish(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("\npermissions: {}\n", workflow)
        build, publish = workflow.split("\n  publish:\n")
        self.assertIn("contents: read", build)
        self.assertNotIn("contents: write", build)
        self.assertIn("contents: write", publish)
        self.assertNotIn("id-token", workflow)
        self.assertIn("persist-credentials: false", build)
        self.assertLess(build.index("merge-base --is-ancestor"), build.index("pip wheel"))
        self.assertIn('cmp "dist/first/$wheel" "dist/second/$wheel"', build)
        self.assertIn("--verify-tag", publish)

    def test_every_library_is_released_by_its_own_tag_and_no_other(self) -> None:
        workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(sorted(path.name for path in (ROOT / "packages").iterdir() if path.is_dir()),
                         sorted(library.name for library in LIBRARIES))
        tag_patterns = re.findall(r'^      - "([a-z-]+-v)\*"$', workflow, flags=re.MULTILINE)
        arms = re.findall(r"^            ([a-z-]+-v)\*\) package=([a-z-]+); prefix=([a-z-]+-v) ;;$",
                          workflow, flags=re.MULTILINE)
        self.assertEqual(sorted(tag_patterns), sorted(prefix for prefix, _ in LIBRARIES.values()))
        self.assertEqual(sorted(arms), sorted((prefix, library.name, prefix)
                                              for library, (prefix, _) in LIBRARIES.items()))
        self.assertIn('*) echo "::error::$TAG names no library"; exit 1 ;;', workflow)

    def test_each_library_needs_nothing_but_what_it_is_allowed(self) -> None:
        """Products bundle it; whatever it pulls in, every product ships."""
        for library, (_, allowed) in LIBRARIES.items():
            with self.subTest(library=library.name):
                pyproject = tomllib.loads((library / "pyproject.toml").read_text(encoding="utf-8"))
                self.assertEqual([re.split(r"[<>=!~ ]", dependency)[0]
                                  for dependency in pyproject["project"]["dependencies"]],
                                 allowed)

    def test_a_library_lock_agrees_with_the_tooling_lock(self) -> None:
        """CI installs the tooling lock and every library's together."""
        tooling = pins(ROOT / "requirements.txt")
        for library in LIBRARIES:
            for name, version in pins(library / "requirements.txt").items():
                if name in tooling:
                    with self.subTest(library=library.name, package=name):
                        self.assertEqual(version, tooling[name])

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

    def test_container_action_verifies_its_scanners_and_uploads_the_sbom_before_scanning(self) -> None:
        action = (ROOT / "actions/container-supply-chain" / "action.yml").read_text(encoding="utf-8")
        order = ["config validate", "container tools", "container sbom", "upload-artifact",
                 "container scan"]
        for earlier, later in zip(order, order[1:]):
            with self.subTest(earlier=earlier, later=later):
                self.assertLess(action.index(earlier), action.index(later))
        # The report is kept when the scan fails: it says why.
        self.assertIn("!cancelled() && inputs.scan == 'true'", action.split("container scan")[1])
        self.assertNotIn("docker pull", action)

    def test_no_action_or_workflow_fetches_and_runs_a_script(self) -> None:
        files = [*ROOT.glob(".github/workflows/*.yml"), *ROOT.glob("actions/*/action.yml")]
        for path in files:
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertIsNone(re.search(r"\b(curl|wget)\b[^\n]*\|\s*(ba|z)?sh\b", text))
                self.assertNotIn("install.sh", text)

    def test_keep_signed_module_keeps_only_through_the_tooling(self) -> None:
        """No signing identity and no signing: the job that keeps cannot sign."""
        action = (ROOT / "actions/keep-signed-module" / "action.yml").read_text(encoding="utf-8")
        self.assertIn("tapio-build signing keep", action)
        self.assertNotIn("azure/login", action)
        self.assertNotIn("signing sign", action)
        self.assertNotIn("gh release", action)

    def test_sign_module_signs_only_through_the_tooling(self) -> None:
        """Login, then one command that signs, verifies and records - nothing else."""
        action = (ROOT / "actions/sign-module" / "action.yml").read_text(encoding="utf-8")
        self.assertLess(action.index("azure/login"), action.index("tapio-build signing sign"))
        self.assertNotIn("az keyvault", action)
        self.assertIn("--summary \"$GITHUB_STEP_SUMMARY\"", action)

    def test_signing_code_carries_no_deployment_of_its_own(self) -> None:
        paths = [*(ROOT / "src/tapio_build_tools/signing").glob("*.py"),
                 *(SIGNING_LIBRARY / "src/tapio_module_signing").glob("*.py")]
        self.assertGreater(len(paths), 8)
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for literal in ["vault.azure.net", "tapiotechnologies", "Tapio-Measurement-Technologies"]:
                with self.subTest(file=path.name, literal=literal):
                    self.assertNotIn(literal, text)
            self.assertIsNone(re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", text),
                              f"a GUID in {path.name}")

    def test_update_check_carries_no_deployment_of_its_own(self) -> None:
        """Which site and which program are the product's to say."""
        paths = [*(UPDATE_CHECK_LIBRARY / "src/tapio_update_check").glob("*.py")]
        self.assertTrue(paths)
        for path in paths:
            text = path.read_text(encoding="utf-8")
            for literal in ["tapiotechnologies", "Tapio-Measurement-Technologies", "cloudfront", "amazonaws.com"]:
                with self.subTest(file=path.name, literal=literal):
                    self.assertNotIn(literal, text)

    def test_publish_downloads_carries_no_deployment_of_its_own(self) -> None:
        """The tooling is public; buckets, roles and addresses belong to the consumer."""
        for name in ["publish-downloads", "publish-release-notes", "publish-archive", "builder-image",
                     "sign-module", "keep-signed-module", "container-supply-chain"]:
            action = (ROOT / "actions" / name / "action.yml").read_text(encoding="utf-8")
            for literal in ["arn:aws:", "amazonaws.com", "s3://", "tapiotechnologies",
                            "vault.azure.net", "/subscriptions/"]:
                with self.subTest(action=name, literal=literal):
                    self.assertNotIn(literal, action)
            self.assertIsNone(re.search(r"[\w.-]+@[\w-]+\.\w+", action), f"an email address in {name}")


if __name__ == "__main__":
    unittest.main()
