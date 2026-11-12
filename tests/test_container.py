from contextlib import redirect_stdout
from datetime import date
import hashlib
import io
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from tapio_build_tools.config import ConfigError, load_config
from tapio_build_tools.container import ContainerError
from tapio_build_tools.container import scan as image
from tapio_build_tools.container import tools
from tapio_build_tools.container.tools import Build, Tool


BINARY = b"\x7fELF pretend scanner\n"
TODAY = date(2026, 11, 12)


def tarball(members: dict[str, bytes], *, kinds: dict[str, bytes] | None = None) -> bytes:
    """A gzipped tar of regular files; *kinds* sets a member's tar type."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as bundle:
        for name, content in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            if kinds and name in kinds:
                info.type = kinds[name]
                info.size = 0
                info.linkname = "/etc/passwd"
                bundle.addfile(info)
                continue
            bundle.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


ARCHIVE = tarball({"LICENSE": b"license", "README.md": b"readme", "scanner": BINARY})
SCANNER = Tool("scanner", "1.2.3", "example/scanner",
               {"linux_amd64": Build(sha(ARCHIVE), sha(BINARY))})


class ToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.fetched: list[str] = []

    def serving(self, data: bytes):
        def fetch(url, stream):
            self.fetched.append(url)
            stream.write(data)
        return fetch

    def install(self, data: bytes = ARCHIVE, tool: Tool = SCANNER) -> Path:
        return tools.install(tool, self.directory, platform="linux_amd64", fetch=self.serving(data))

    def test_downloads_from_the_github_release_and_checks_both_digests(self) -> None:
        binary = self.install()
        self.assertEqual(self.fetched, [
            "https://github.com/example/scanner/releases/download/v1.2.3/scanner_1.2.3_linux_amd64.tar.gz"])
        self.assertEqual(binary.read_bytes(), BINARY)
        self.assertTrue(os.access(binary, os.X_OK))
        self.assertEqual(binary, self.directory / "scanner-1.2.3-linux_amd64" / "scanner")
        self.assertEqual(sorted(path.name for path in binary.parent.iterdir()), ["scanner"])

    def test_a_binary_already_there_is_checked_and_not_downloaded_again(self) -> None:
        self.install()
        self.fetched.clear()
        self.install()
        self.assertEqual(self.fetched, [])

    def test_a_binary_changed_on_disk_is_replaced_from_the_release(self) -> None:
        binary = self.install()
        binary.write_bytes(b"something else")
        self.fetched.clear()
        self.assertEqual(self.install().read_bytes(), BINARY)
        self.assertEqual(len(self.fetched), 1)

    def test_an_archive_with_another_digest_is_refused_and_leaves_nothing(self) -> None:
        other = tarball({"scanner": b"a different scanner"})
        with self.assertRaisesRegex(ContainerError, f"has SHA-256 {sha(other)}; {sha(ARCHIVE)} is pinned"):
            self.install(other)
        home = self.directory / "scanner-1.2.3-linux_amd64"
        self.assertEqual(list(home.iterdir()), [])

    def test_a_binary_with_another_digest_is_refused_even_from_a_pinned_archive(self) -> None:
        other = tarball({"scanner": b"a different scanner"})
        tool = Tool("scanner", "1.2.3", "example/scanner",
                    {"linux_amd64": Build(sha(other), sha(BINARY))})
        with self.assertRaisesRegex(ContainerError, "scanner in scanner_1.2.3_linux_amd64.tar.gz has SHA-256"):
            self.install(other, tool)
        self.assertFalse((self.directory / "scanner-1.2.3-linux_amd64" / "scanner").exists())

    def test_only_a_single_regular_file_at_the_root_is_taken(self) -> None:
        twice = io.BytesIO()
        with tarfile.open(fileobj=twice, mode="w:gz") as bundle:
            for content in (BINARY, b"another"):
                info = tarfile.TarInfo("scanner")
                info.size = len(content)
                bundle.addfile(info, io.BytesIO(content))
        cases = {
            "nested": tarball({"bin/scanner": BINARY}),
            "link": tarball({"scanner": b""}, kinds={"scanner": tarfile.SYMTYPE}),
            "twice": twice.getvalue(),
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                tool = Tool("scanner", "1.2.3", "example/scanner",
                            {"linux_amd64": Build(sha(data), sha(BINARY))})
                with self.assertRaisesRegex(ContainerError, "holds no single scanner binary"):
                    self.install(data, tool)

    def test_a_download_past_the_size_cap_is_stopped_before_its_digest_is_checked(self) -> None:
        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        written = io.BytesIO()
        with patch.object(tools, "urlopen", return_value=Response(b"x" * 5000)), \
                self.assertRaisesRegex(ContainerError, "is larger than 4096 bytes; stopped"):
            tools.download("https://github.com/example/scanner/releases/download/v1/x.tar.gz",
                           written, limit=4096)
        self.assertLessEqual(len(written.getvalue()), 4096)
        self.assertEqual(tools.MAXIMUM_ARCHIVE_BYTES, 256 << 20)

    def test_a_platform_without_a_pinned_build_is_refused(self) -> None:
        with self.assertRaisesRegex(ContainerError, "no pinned scanner build for linux_arm64"):
            tools.install(SCANNER, self.directory, platform="linux_arm64", fetch=self.serving(ARCHIVE))

    def test_platforms_are_named_as_anchore_names_them(self) -> None:
        self.assertEqual(tools.current_platform("Linux", "x86_64"), "linux_amd64")
        self.assertEqual(tools.current_platform("Linux", "aarch64"), "linux_arm64")
        with self.assertRaisesRegex(ContainerError, "no pinned scanner builds for darwin arm64"):
            tools.current_platform("Darwin", "arm64")

    def test_the_pins_name_full_digests_for_both_runner_architectures(self) -> None:
        for tool in tools.TOOLS:
            with self.subTest(tool=tool.name):
                self.assertEqual(sorted(tool.builds), ["linux_amd64", "linux_arm64"])
                self.assertRegex(tool.version, r"^\d+\.\d+\.\d+$")
                self.assertTrue(tool.url("linux_amd64").startswith(
                    f"https://github.com/anchore/{tool.name}/releases/download/v{tool.version}/"))
                for build in tool.builds.values():
                    self.assertRegex(build.archive_sha256, r"^[0-9a-f]{64}$")
                    self.assertRegex(build.binary_sha256, r"^[0-9a-f]{64}$")

    def test_tools_live_under_the_runner_temp_in_actions(self) -> None:
        with patch.dict(os.environ, {"RUNNER_TEMP": "/runner/tmp"}):
            self.assertEqual(tools.default_directory(), Path("/runner/tmp/tapio-container-tools"))


CONFIG = """schema-version = 1
[organization]
name = "Example"
[products.lambda]
name = "Example Lambda"
"""

PYTHON = """
[ecosystems.python]
version = "3.12"
[[ecosystems.python.requirements]]
name = "runtime"
lock = "requirements.txt"
[[ecosystems.python.accepted-risks]]
id = "GHSA-h35f-9h28-mq5c"
package = "setuptools"
reason = "Held below 80 by zappa; see R-08."
review-by = 2027-01-31
"""

CONTAINER = """
[container]
fail-on = "high"
[[container.accepted-risks]]
id = "CVE-2026-2001"
package = "openssl-libs"
reason = "The Lambda base image ships it; no TLS is terminated in the function."
review-by = 2027-01-31
"""


def grype_match(package, version, kind, vid, severity, state="fixed", fixes=("9.9.9",), related=()):
    return {
        "vulnerability": {"id": vid, "dataSource": "", "severity": severity, "urls": [], "cvss": [],
                          "fix": {"versions": list(fixes) if state == "fixed" else [], "state": state},
                          "advisories": [], "risk": 0.0},
        "relatedVulnerabilities": [{"id": item, "dataSource": "", "urls": [], "cvss": []}
                                   for item in related],
        "matchDetails": [],
        "artifact": {"id": f"{package}-{version}", "name": package, "version": version, "type": kind,
                     "locations": [], "language": "", "licenses": [], "cpes": [], "purl": "",
                     "upstreams": []},
    }


class ImageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "requirements.txt").write_text("setuptools==79.0.1\n", encoding="utf-8")
        self.commands: list[tuple[list[str], dict]] = []
        environment = patch.dict(os.environ, {"GITHUB_ACTIONS": "", "GRYPE_DB_AUTO_UPDATE": "false",
                                              "SYFT_EXCLUDE": "/usr"})
        environment.start()
        self.addCleanup(environment.stop)
        installed = patch.object(image, "install", side_effect=lambda tool, directory: Path(f"/tools/{tool.name}"))
        installed.start()
        self.addCleanup(installed.stop)

    def config(self, text: str):
        (self.root / "build-tooling.toml").write_text(text, encoding="utf-8")
        return load_config(self.root)

    def grype(self, *found):
        def run(command, **kwargs):
            self.commands.append((command, kwargs))
            [output] = [value.split("=", 1)[1] for value in command if value.startswith("json=")]
            Path(output).write_text(json.dumps({"matches": list(found), "source": {"type": "sbom"}}),
                                    encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)
        return run

    def scan(self, config, *found, **options):
        stdout = StringIO()
        with patch.object(image.subprocess, "run", side_effect=self.grype(*found)), redirect_stdout(stdout):
            try:
                return image.scan(config, sbom=self.root / "image.syft.json", report=self.root / "report.json",
                                  tools=self.root / "tools", today=options.pop("today", TODAY),
                                  subject="example:local", **options)
            finally:
                self.output = stdout.getvalue()

    def test_grype_reads_the_syft_json_in_an_empty_directory_without_inherited_settings(self) -> None:
        self.scan(self.config(CONFIG + CONTAINER))
        [(command, kwargs)] = self.commands
        self.assertEqual(command, ["/tools/grype", f"sbom:{self.root / 'image.syft.json'}", "--output", "table",
                                   "--output", f"json={self.root / 'report.json'}"])
        self.assertNotEqual(Path(kwargs["cwd"]), self.root)
        self.assertNotIn("GRYPE_DB_AUTO_UPDATE", kwargs["env"])
        self.assertEqual(kwargs["env"]["GRYPE_CHECK_FOR_APP_UPDATE"], "false")
        self.assertTrue(kwargs["check"])

    def test_a_fixable_finding_at_the_threshold_fails(self) -> None:
        with self.assertRaisesRegex(ContainerError, "example:local has fixable vulnerabilities at or above high: "
                                                    "curl 8.0.0 CVE-2026-3001 is not accepted"):
            self.scan(self.config(CONFIG + "[container]\n"), grype_match("curl", "8.0.0", "rpm", "CVE-2026-3001", "High"))
        self.assertIn("vulnerable: curl 8.0.0 CVE-2026-3001: high; fixed in 9.9.9", self.output)

    def test_below_the_threshold_or_without_a_fix_passes(self) -> None:
        self.scan(self.config(CONFIG + "[container]\n"),
                  grype_match("curl", "8.0.0", "rpm", "CVE-2026-3001", "Medium"),
                  grype_match("glibc", "2.34", "rpm", "CVE-2026-3002", "Critical", state="not-fixed"),
                  grype_match("bash", "5.2", "rpm", "CVE-2026-3003", "Critical", state="wont-fix"))
        self.assertIn("3 finding(s); at or above high with a fix: 0 (0 not accepted, 0 accepted); "
                      "below high or without a fix: 3 (0 accepted)", self.output)

    def test_the_summary_counts_blocking_and_passing_findings_apart(self) -> None:
        with self.assertRaises(ContainerError):
            self.scan(self.config(CONFIG + CONTAINER),
                      grype_match("openssl-libs", "3.0.8", "rpm", "CVE-2026-2001", "Low"),
                      grype_match("curl", "8.0.0", "rpm", "CVE-2026-3001", "Medium"),
                      grype_match("glibc", "2.34", "rpm", "CVE-2026-3002", "High"))
        self.assertIn("3 finding(s); at or above high with a fix: 1 (1 not accepted, 0 accepted); "
                      "below high or without a fix: 2 (1 accepted)", self.output)

    def test_the_threshold_comes_from_the_config_or_the_command(self) -> None:
        medium = grype_match("curl", "8.0.0", "rpm", "CVE-2026-3001", "Medium")
        with self.assertRaises(ContainerError):
            self.scan(self.config(CONFIG + '[container]\nfail-on = "medium"\n'), medium)
        with self.assertRaises(ContainerError):
            self.scan(self.config(CONFIG + "[container]\n"), medium, fail_on="low")
        self.scan(self.config(CONFIG + '[container]\nfail-on = "medium"\n'), medium, fail_on="critical")

    def test_an_unknown_severity_with_a_fix_counts_as_at_the_threshold(self) -> None:
        with self.assertRaises(ContainerError):
            self.scan(self.config(CONFIG + "[container]\n"), grype_match("curl", "8.0.0", "rpm", "CVE-2026-3001", "Unknown"),
                      fail_on="critical")

    def test_a_container_entry_accepts_a_distribution_advisory_by_its_cve(self) -> None:
        self.scan(self.config(CONFIG + CONTAINER),
                  grype_match("openssl-libs", "3.0.8", "rpm", "ALAS2023-2026-900", "High",
                              related=["CVE-2026-2001"]))
        self.assertIn("accepted: openssl-libs 3.0.8 ALAS2023-2026-900 (CVE-2026-2001): high; fixed in 9.9.9 - "
                      "container.accepted-risks[0], review by 2027-01-31: The Lambda base image", self.output)

    def test_an_ecosystem_entry_accepts_that_ecosystems_packages_in_the_image(self) -> None:
        config = self.config(CONFIG + PYTHON)
        self.scan(config, grype_match("setuptools", "79.0.1", "python", "GHSA-h35f-9h28-mq5c", "High",
                                      related=["CVE-2026-59890"]))
        self.assertIn("ecosystems.python.accepted-risks[0]", self.output)
        with self.assertRaisesRegex(ContainerError, "setuptools 79.0.1 GHSA-h35f-9h28-mq5c is not accepted"):
            self.scan(config, grype_match("setuptools", "79.0.1", "rpm", "GHSA-h35f-9h28-mq5c", "High"))

    def test_a_python_entry_by_pysec_id_is_named_when_the_image_needs_it(self) -> None:
        pysec = PYTHON.replace("GHSA-h35f-9h28-mq5c", "PYSEC-2026-3447")
        finding = grype_match("setuptools", "79.0.1", "python", "GHSA-h35f-9h28-mq5c", "High",
                              related=["CVE-2026-59890"])
        with self.assertRaises(ContainerError):
            self.scan(self.config(CONFIG + pysec), finding)
        self.assertIn("warning: example:local: ecosystems.python.accepted-risks[0] accepts "
                      "PYSEC-2026-3447 for setuptools, and grype has no PYSEC ids, so it accepts "
                      "nothing in the image", self.output)

    def test_a_pysec_entry_beside_a_ghsa_one_that_covers_the_image_is_not_named(self) -> None:
        both = PYTHON + """
[[ecosystems.python.accepted-risks]]
id = "PYSEC-2026-3447"
package = "setuptools"
reason = "The same advisory, as pip-audit names it."
review-by = 2027-01-31
"""
        config = self.config(CONFIG + both)
        self.assertEqual([entry.id for entry in config.python.accepted_risks],
                         ["GHSA-h35f-9h28-mq5c", "PYSEC-2026-3447"])
        self.scan(config, grype_match("setuptools", "79.0.1", "python", "GHSA-h35f-9h28-mq5c", "High"))
        self.assertNotIn("PYSEC", self.output)

    def test_an_expired_entry_fails_a_fixable_finding(self) -> None:
        with self.assertRaisesRegex(ContainerError, "until 2027-01-31, which has passed"):
            self.scan(self.config(CONFIG + CONTAINER),
                      grype_match("openssl-libs", "3.0.8", "rpm", "CVE-2026-2001", "High"),
                      today=date(2027, 2, 1))

    def test_only_container_entries_are_flagged_when_they_match_nothing(self) -> None:
        self.scan(self.config(CONFIG + PYTHON + CONTAINER))
        self.assertIn("warning: example:local: container.accepted-risks[0] accepts CVE-2026-2001 for "
                      "openssl-libs, which no finding matches any more", self.output)
        self.assertNotIn("ecosystems.python.accepted-risks[0]", self.output)

    def test_a_container_entry_matching_a_finding_below_the_threshold_is_not_stale(self) -> None:
        self.scan(self.config(CONFIG + CONTAINER),
                  grype_match("openssl-libs", "3.0.8", "rpm", "CVE-2026-2001", "Low"))
        self.assertNotIn("warning", self.output)

    def test_the_same_package_at_two_paths_is_one_finding(self) -> None:
        twice = grype_match("requests", "2.0.0", "python", "GHSA-2222-3333-4444", "Low")
        self.scan(self.config(CONFIG + "[container]\n"), twice, dict(twice))
        self.assertIn("1 finding(s)", self.output)

    def test_grype_failing_or_writing_nothing_fails_the_scan(self) -> None:
        config = self.config(CONFIG + "[container]\n")
        with patch.object(image.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "grype")), \
                self.assertRaisesRegex(ContainerError, "grype could not scan the image"):
            image.scan(config, sbom=self.root / "s.json", report=self.root / "r.json", tools=self.root)
        with patch.object(image.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                self.assertRaisesRegex(ContainerError, "grype wrote no readable report"):
            image.scan(config, sbom=self.root / "s.json", report=self.root / "missing.json", tools=self.root)

    def test_syft_catalogues_the_local_image_once_into_both_documents(self) -> None:
        config = self.config(CONFIG + "[container]\n")
        output = self.root / "dist" / "image.cdx.json"

        def syft(command, **kwargs):
            self.commands.append((command, kwargs))
            for value in command:
                if "=" in value and value.split("=", 1)[0] in {"cyclonedx-json", "syft-json"}:
                    Path(value.split("=", 1)[1]).write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(image.subprocess, "run", side_effect=syft):
            written = image.generate_sbom(config, image="example:local", output=output, product_id="lambda",
                                          version="1.4.0", tools=self.root / "tools")
        self.assertEqual(written, (output, self.root / "dist" / "image.syft.json"))
        [(command, kwargs)] = self.commands
        self.assertEqual(command, [
            "/tools/syft", "scan", "docker:example:local",
            "--output", f"cyclonedx-json={output}", "--output", f"syft-json={written[1]}",
            "--source-name", "lambda", "--source-version", "1.4.0",
        ])
        self.assertNotIn("SYFT_EXCLUDE", kwargs["env"])
        self.assertEqual(kwargs["env"]["SYFT_CHECK_FOR_APP_UPDATE"], "false")

    def test_syft_writing_nothing_fails_the_sbom(self) -> None:
        with patch.object(image.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                self.assertRaisesRegex(ContainerError, "syft wrote no"):
            image.generate_sbom(self.config(CONFIG + "[container]\n"), image="example:local", output=self.root / "x.cdx.json",
                                tools=self.root)


class ContainerConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def load(self, text: str):
        (self.root / "build-tooling.toml").write_text(text, encoding="utf-8")
        return load_config(self.root)

    def test_a_container_table_is_configuration_enough_on_its_own(self) -> None:
        container = self.load(CONFIG + CONTAINER).container
        self.assertEqual(container.fail_on, "high")
        [risk] = container.accepted_risks
        self.assertEqual((risk.id, risk.package, risk.ecosystem), ("CVE-2026-2001", "openssl-libs", "container"))
        self.assertEqual(self.load(CONFIG + "[container]\n").container.fail_on, "high")

    def test_rejects_what_the_scan_could_not_use(self) -> None:
        cases = [
            ('fail-on = "high"', 'fail-on = "severe"', "container.fail-on is invalid: severe"),
            ('fail-on = "high"', 'fail-on = "high"\nscanner = "trivy"', "unknown container key"),
            ('id = "CVE-2026-2001"', 'id = "PYSEC-2026-1"', "never PYSEC"),
            ('package = "openssl-libs"', 'package = "openssl libs"', "not a package name"),
            ("review-by = 2027-01-31\n", "", "review-by is required"),
        ]
        for old, new, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ConfigError, message):
                    self.load(CONFIG + CONTAINER.replace(old, new))


if __name__ == "__main__":
    unittest.main()
