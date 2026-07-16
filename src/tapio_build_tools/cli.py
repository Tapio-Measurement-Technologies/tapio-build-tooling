"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys

from tapio_build_tools.config import ConfigError, load_config
from tapio_build_tools.ecosystems.node.audit import AuditError as NodeAuditError
from tapio_build_tools.ecosystems.node.audit import audit as audit_node
from tapio_build_tools.ecosystems.node.sbom import SbomError as NodeSbomError
from tapio_build_tools.ecosystems.node.sbom import generate_sbom as generate_node_sbom
from tapio_build_tools.ecosystems.python.audit import AuditError, audit
from tapio_build_tools.ecosystems.python.requirements import (
    RequirementsError,
    compile_requirements,
)
from tapio_build_tools.ecosystems.python.sbom import SbomError, generate_sbom


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tapio-build")
    parser.add_argument("--project", default=".", help="consumer project root")
    parser.add_argument("--config", default="build-tooling.toml", help="configuration path")
    commands = parser.add_subparsers(dest="command", required=True)
    config = commands.add_parser("config", help="configuration operations")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    config_commands.add_parser("validate", help="validate configuration and referenced files")

    python = commands.add_parser("python", help="Python ecosystem operations")
    python_commands = python.add_subparsers(dest="python_command", required=True)
    requirements = python_commands.add_parser("requirements", help="requirement lock operations")
    requirement_commands = requirements.add_subparsers(dest="requirements_command", required=True)
    compile_parser = requirement_commands.add_parser("compile", help="compile hashed locks")
    compile_parser.add_argument("--group", help="compile one configured requirement group")
    compile_mode = compile_parser.add_mutually_exclusive_group()
    compile_mode.add_argument("--check", action="store_true", help="fail if locks would change")
    compile_mode.add_argument("--upgrade", action="store_true", help="upgrade allowed versions")

    audit_parser = python_commands.add_parser("audit", help="audit a hashed requirement lock")
    audit_parser.add_argument("--group", required=True, help="configured requirement group")

    sbom = python_commands.add_parser("sbom", help="generate CycloneDX evidence")
    sbom.add_argument("--group", required=True, help="configured requirement group")
    sbom.add_argument("--product", help="configured product ID")
    sbom.add_argument("--output", required=True, help="output CycloneDX JSON path")
    sbom.add_argument("--version", default=os.environ.get("GITHUB_REF_NAME", "0.0.0+local"))
    sbom.add_argument("--commit-sha", help="source commit SHA")
    sbom.add_argument("--platform", dest="build_platform", help="target platform")
    sbom.add_argument("--build-timestamp", help="UTC evidence timestamp")
    sbom.add_argument("--spec-version", default="1.6", choices=("1.6", "1.7"))
    sbom.add_argument("--artifact", help="final artifact represented by this SBOM")
    sbom.add_argument("--artifact-kind", choices=("pyinstaller",))
    sbom.add_argument("--pyinstaller-version", help="embedded PyInstaller version")

    node = commands.add_parser("node", help="Node/npm ecosystem operations")
    node_commands = node.add_subparsers(dest="node_command", required=True)
    node_commands.add_parser("audit", help="audit the configured npm package lock")
    node_sbom = node_commands.add_parser("sbom", help="generate CycloneDX evidence")
    node_sbom.add_argument("--product", help="configured product ID")
    node_sbom.add_argument("--output", required=True, help="output CycloneDX JSON path")
    node_sbom.add_argument("--version", default=os.environ.get("GITHUB_REF_NAME", "0.0.0+local"))
    node_sbom.add_argument("--commit-sha", help="source commit SHA")
    node_sbom.add_argument("--platform", dest="build_platform", help="target platform")
    node_sbom.add_argument("--build-timestamp", help="UTC evidence timestamp")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.project, args.config)
        if args.command == "config" and args.config_command == "validate":
            print(f"Valid: {config.path}")
            return 0
        if args.command == "python" and args.python_command == "requirements":
            results = compile_requirements(
                config,
                group_name=args.group,
                check=args.check,
                upgrade=args.upgrade,
            )
            for result in results:
                print(f"{result.group}: {result.status}")
            return 0
        if args.command == "python" and args.python_command == "audit":
            audit(config, args.group)
            return 0
        if args.command == "python" and args.python_command == "sbom":
            output = generate_sbom(
                config,
                group_name=args.group,
                product_id=args.product,
                output=args.output,
                version=args.version,
                commit_sha=args.commit_sha,
                build_platform=args.build_platform,
                build_timestamp=args.build_timestamp,
                spec_version=args.spec_version,
                artifact=args.artifact,
                artifact_kind=args.artifact_kind,
                pyinstaller_version=args.pyinstaller_version,
            )
            print(f"Generated CycloneDX SBOM: {output}")
            return 0
        if args.command == "node" and args.node_command == "audit":
            audit_node(config)
            return 0
        if args.command == "node" and args.node_command == "sbom":
            output = generate_node_sbom(
                config,
                product_id=args.product,
                output=args.output,
                version=args.version,
                commit_sha=args.commit_sha,
                build_platform=args.build_platform,
                build_timestamp=args.build_timestamp,
            )
            print(f"Generated CycloneDX SBOM: {output}")
            return 0
    except (
        AuditError,
        ConfigError,
        NodeAuditError,
        NodeSbomError,
        RequirementsError,
        SbomError,
        ValueError,
    ) as exc:
        print(f"tapio-build: error: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2
