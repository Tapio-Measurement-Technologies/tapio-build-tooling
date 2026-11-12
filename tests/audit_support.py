"""Stand-ins for pip-audit and npm audit: each writes the report the real one would."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess


def pip_audit(*dependencies: dict, returncode: int | None = None, calls: list | None = None):
    """A subprocess.run that writes pip-audit's JSON report for *dependencies*.

    Each dependency is {"name", "version", "vulns": [{"id", "aliases", "fix_versions"}]}.
    pip-audit exits 1 when it reports a vulnerability, 0 otherwise.
    """
    found = any(dependency.get("vulns") for dependency in dependencies)
    code = (1 if found else 0) if returncode is None else returncode

    def run(command, **kwargs):
        if calls is not None:
            calls.append(command)
        output = Path(command[command.index("--output") + 1])
        output.write_text(json.dumps({"dependencies": list(dependencies), "fixes": []}),
                          encoding="utf-8")
        return subprocess.CompletedProcess(command, code)

    return run


def dependency(name: str, version: str, *vulns: tuple[str, list[str], list[str]]) -> dict:
    """One dependency in pip-audit's report: (id, aliases, fix versions) per vulnerability."""
    return {
        "name": name,
        "version": version,
        "vulns": [{"id": vid, "aliases": aliases, "fix_versions": fixes}
                  for vid, aliases, fixes in vulns],
    }


def npm_report(*advisories: tuple[str, str, str], effects: dict[str, list[str]] | None = None) -> dict:
    """npm audit's version 2 report: (package, GHSA id, severity) per advisory.

    *effects* maps a package that is vulnerable only through others to their names.
    """
    vulnerabilities: dict[str, dict] = {}
    for package, ghsa, severity in advisories:
        entry = vulnerabilities.setdefault(package, {
            "name": package, "severity": severity, "isDirect": False, "via": [],
            "effects": [], "range": "*", "nodes": [f"node_modules/{package}"], "fixAvailable": False,
        })
        entry["via"].append({
            "source": 1000000 + len(entry["via"]), "name": package, "dependency": package,
            "title": f"An advisory against {package}", "url": f"https://github.com/advisories/{ghsa}",
            "severity": severity, "cwe": [], "cvss": {}, "range": "*",
        })
    for package, through in (effects or {}).items():
        vulnerabilities[package] = {
            "name": package, "severity": "low", "isDirect": True, "via": through, "effects": [],
            "range": "*", "nodes": [f"node_modules/{package}"], "fixAvailable": False,
        }
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulnerabilities,
        "metadata": {"vulnerabilities": {"total": len(vulnerabilities)}},
    }


def npm_audit(report: dict, returncode: int | None = None, calls: list | None = None):
    """A subprocess.run that prints *report* as npm audit --json would."""
    code = (1 if report.get("vulnerabilities") else 0) if returncode is None else returncode

    def run(command, **kwargs):
        if calls is not None:
            calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, code, stdout=json.dumps(report))

    return run
