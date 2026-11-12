"""An image's SBOM, written by syft, and its vulnerabilities, found by grype.

syft catalogues the image once and writes two documents: the CycloneDX SBOM
that is kept as evidence, and its own JSON, which grype reads back. The scan
therefore judges exactly the packages the SBOM lists, and the image is not
read a second time.

A registry's basic scan looks at operating-system packages once, when the
image is pushed. This one sees the Python and npm packages too, runs on every
build, and fails the build on a finding at or above the configured severity
for which a fix is available - unless an accepted risk covers it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
import os
from pathlib import Path
import subprocess
import tempfile

from tapio_build_tools import risks
from tapio_build_tools.config import SEVERITIES, Config, Container
from tapio_build_tools.container import ContainerError
from tapio_build_tools.container.tools import GRYPE, SYFT, install

# The package types grype reports whose ecosystem has accepted risks of its own.
ECOSYSTEMS = {"python": "python", "npm": "node"}


def _environment() -> dict[str, str]:
    """The caller's environment without any setting for syft or grype.

    Both read configuration from SYFT_* and GRYPE_* variables, and from a
    .syft.yaml or .grype.yaml in the directory they run in, which could leave
    packages out of the catalogue or matches out of the report. They are run
    in an empty directory, with only the settings given here.
    """
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("SYFT_", "GRYPE_"))}
    environment["SYFT_CHECK_FOR_APP_UPDATE"] = "false"
    environment["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    return environment


def _run(command: list[str], what: str) -> None:
    with tempfile.TemporaryDirectory(prefix="tapio-container-") as empty:
        try:
            subprocess.run(command, cwd=empty, env=_environment(), check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ContainerError(f"{what} failed") from exc


def syft_output_for(output: Path) -> Path:
    """Where syft's own JSON goes beside a CycloneDX *output*, unless told otherwise."""
    stem = output.name.removesuffix(".json").removesuffix(".cdx")
    return output.with_name(f"{stem}.syft.json")


def generate_sbom(
    config: Config,
    *,
    image: str,
    output: Path,
    syft_output: Path | None = None,
    product_id: str | None = None,
    version: str | None = None,
    tools: Path,
) -> tuple[Path, Path]:
    """Write the image's CycloneDX SBOM and syft's JSON of it; return both paths.

    *image* is read from the local Docker daemon, where the job built it: no
    registry is asked for it.
    """
    output = output.resolve()
    syft_output = (syft_output or syft_output_for(output)).resolve()
    command = [str(install(SYFT, tools)), "scan", f"docker:{image}",
               "--output", f"cyclonedx-json={output}", "--output", f"syft-json={syft_output}"]
    if product_id is not None:
        command += ["--source-name", config.product(product_id).id]
    if version:
        command += ["--source-version", version]
    output.parent.mkdir(parents=True, exist_ok=True)
    syft_output.parent.mkdir(parents=True, exist_ok=True)
    _run(command, f"syft could not catalogue {image}")
    for path in (output, syft_output):
        if not path.is_file():
            raise ContainerError(f"syft wrote no {path}")
    return output, syft_output


@dataclass(frozen=True)
class Match:
    """One of grype's matches, as an accepted risk is matched against it."""

    finding: risks.Finding
    fixable: bool

    def blocks(self, threshold: str) -> bool:
        """At or above *threshold* with a fix out; an unknown severity counts as at it."""
        severity = (self.finding.severity or "unknown").lower()
        rank = SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)
        return self.fixable and rank >= SEVERITIES.index(threshold)


def matches(report: dict) -> list[Match]:
    """grype's JSON report, one Match per package and vulnerability."""
    raw = report.get("matches")
    if not isinstance(raw, list):
        raise ContainerError("grype's report has no matches list")
    found: dict[risks.Finding, bool] = {}
    for match in raw:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix = vulnerability.get("fix") or {}
        fixable = fix.get("state") == "fixed"
        kind = str(artifact.get("type") or "unknown")
        finding = risks.Finding(
            package=str(artifact.get("name")),
            version=str(artifact.get("version")),
            id=str(vulnerability.get("id")),
            ecosystem=ECOSYSTEMS.get(kind, kind),
            aliases=frozenset(str(related.get("id"))
                              for related in match.get("relatedVulnerabilities") or []),
            severity=vulnerability.get("severity"),
            fixed_in=tuple(fix.get("versions") or ()) if fixable else (),
        )
        # The same package at two paths in the image is one finding.
        found[finding] = found.get(finding, False) or fixable
    return [Match(finding, fixable) for finding, fixable in found.items()]


def scan(
    config: Config,
    *,
    sbom: Path,
    report: Path,
    tools: Path,
    fail_on: str | None = None,
    today: date | None = None,
    subject: str = "image",
) -> risks.Assessment:
    """Scan syft's JSON at *sbom*, write grype's report to *report*, and judge it.

    Fails on a finding at or above the threshold with a fix available that no
    accepted risk covers: the container's own entries, and for a Python or npm
    package in the image that ecosystem's. Only the container's entries are
    flagged when they match nothing - an ecosystem's are its own audit's to
    flag, and a scan of an image without that package proves nothing.
    """
    container = config.container or Container()
    threshold = fail_on or container.fail_on
    if threshold not in SEVERITIES:
        raise ContainerError(f"--fail-on must be one of {', '.join(SEVERITIES)}")
    sbom = sbom.resolve()
    report = report.resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    _run([str(install(GRYPE, tools)), f"sbom:{sbom}", "--output", "table",
          "--output", f"json={report}"], "grype could not scan the image")
    try:
        document = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ContainerError(f"grype wrote no readable report to {report}") from exc

    found = matches(document)
    blocking = {match.finding for match in found if match.blocks(threshold)}
    accepted_risks = [*container.accepted_risks,
                      *(config.python.accepted_risks if config.python else ()),
                      *(config.node.accepted_risks if config.node else ())]
    judged = risks.assess([match.finding for match in found], accepted_risks,
                          on=today or risks.today())
    assessment = risks.Assessment(
        accepted=tuple((finding, risk) for finding, risk in judged.accepted),
        expired=tuple((finding, risk) for finding, risk in judged.expired if finding in blocking),
        open=tuple(finding for finding in judged.open if finding in blocking),
        stale=tuple(risk for risk in judged.stale if risk.ecosystem == "container"),
    )
    risks.report(assessment, subject=subject, summary=False)
    passed = len(found) - len(assessment.open) - len(assessment.expired) - len(assessment.accepted)
    print(f"{subject}: {len(found)} finding(s); {len(assessment.open) + len(assessment.expired)} "
          f"at or above {threshold} with a fix and not accepted, {len(assessment.accepted)} "
          f"accepted, {passed} below {threshold} or without a fix")
    if assessment.failed:
        raise ContainerError(f"{subject} has fixable vulnerabilities at or above {threshold}: "
                             f"{assessment.failure()}")
    return assessment
