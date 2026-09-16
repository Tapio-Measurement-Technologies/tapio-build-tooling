"""Command-line interface."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import tempfile

from tapio_build_tools.config import ConfigError, load_config
from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.publish import (
    publish_downloads,
    publish_notes,
    publish_root_index,
    render_only,
)
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

    downloads = commands.add_parser("downloads", help="release download site operations")
    downloads_commands = downloads.add_subparsers(dest="downloads_command", required=True)
    publish = downloads_commands.add_parser("publish", help="publish a release to the download bucket")
    publish.add_argument("--version", default=os.environ.get("GITHUB_REF_NAME"), help="release tag")
    publish.add_argument("--bucket", required=True, help="S3 bucket name")
    publish.add_argument("--base-url", required=True, help="public URL of the bucket root")
    publish.add_argument("--output-dir", type=Path, help="where the site tree is written; a new temporary directory by default")
    publish.add_argument("--program", action="append", dest="programs", help="configured program ID; repeatable; all by default")
    publish.add_argument("--dry-run", action="store_true", help="write the site tree and list the uploads without uploading")
    publish.add_argument("--force", action="store_true", help="replace a version already published with different files")
    publish.add_argument("--root-index", action="store_true", help="also write the bucket root index of all programs")
    publish.add_argument("--existing-manifest", type=Path, help="use this releases.json instead of fetching the bucket's")
    publish.add_argument("--released", help="UTC release timestamp; now by default")
    publish.add_argument("--commit", help="source commit SHA")
    publish.add_argument("--aws-region", help="region passed to the aws CLI")
    root = downloads_commands.add_parser("root-index", help="write the bucket-root page listing every program")
    root.add_argument("--bucket", required=True, help="S3 bucket name")
    root.add_argument("--output-dir", type=Path, help="where the page is written; a new temporary directory by default")
    root.add_argument("--dry-run", action="store_true", help="read the bucket and write the page without uploading")
    root.add_argument("--aws-region", help="region passed to the aws CLI")
    notes = downloads_commands.add_parser("notes", help="put a release's notes on its published pages")
    notes.add_argument("--version", default=os.environ.get("GITHUB_REF_NAME"), help="release tag")
    notes.add_argument("--notes-file", type=Path, required=True, help="Markdown notes; an empty file clears them")
    notes.add_argument("--bucket", required=True, help="S3 bucket name")
    notes.add_argument("--output-dir", type=Path, help="where the pages are written; a new temporary directory by default")
    notes.add_argument("--program", action="append", dest="programs", help="configured program ID; repeatable; all by default")
    notes.add_argument("--dry-run", action="store_true", help="read the bucket and write the pages without uploading")
    notes.add_argument("--aws-region", help="region passed to the aws CLI")
    render = downloads_commands.add_parser("render", help="write a program's pages from a manifest")
    render.add_argument("--program", required=True, help="configured program ID")
    render.add_argument("--manifest", type=Path, required=True, help="releases.json to render")
    render.add_argument("--output-dir", type=Path, required=True, help="where the pages are written")
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
        if args.command == "downloads" and args.downloads_command == "publish":
            if not args.version:
                parser.error("--version is required outside GitHub Actions")
            output_dir = args.output_dir or Path(tempfile.mkdtemp(prefix="tapio-downloads-"))
            summary = publish_downloads(
                config,
                version=args.version,
                bucket=args.bucket,
                base_url=args.base_url,
                output_dir=output_dir,
                programs=args.programs,
                dry_run=args.dry_run,
                force=args.force,
                root_index=args.root_index,
                existing_manifest=args.existing_manifest,
                released=args.released,
                commit=args.commit,
                aws_region=args.aws_region,
            )
            verb = "Would publish" if args.dry_run else "Published"
            for result in summary.programs.values():
                state = "latest" if result.latest else "not latest"
                print(f"{verb} {result.slug} {summary.version} ({state}): {result.version_url}")
            print(f"Site tree and summary: {output_dir}")
            return 0
        if args.command == "downloads" and args.downloads_command == "notes":
            if not args.version:
                parser.error("--version is required outside GitHub Actions")
            output_dir = args.output_dir or Path(tempfile.mkdtemp(prefix="tapio-downloads-"))
            updated = publish_notes(
                config,
                version=args.version,
                notes=args.notes_file.read_text(encoding="utf-8"),
                bucket=args.bucket,
                output_dir=output_dir,
                programs=args.programs,
                dry_run=args.dry_run,
                aws_region=args.aws_region,
            )
            for program_id, done in updated.items():
                state = "notes updated" if done else "not published there; nothing to do"
                print(f"{program_id} {args.version}: {state}")
            return 0
        if args.command == "downloads" and args.downloads_command == "root-index":
            output_dir = args.output_dir or Path(tempfile.mkdtemp(prefix="tapio-downloads-"))
            publish_root_index(
                config,
                bucket=args.bucket,
                output_dir=output_dir,
                dry_run=args.dry_run,
                aws_region=args.aws_region,
            )
            verb = "Would publish" if args.dry_run else "Published"
            print(f"{verb} the root index; page and commands in {output_dir}")
            return 0
        if args.command == "downloads" and args.downloads_command == "render":
            pages = render_only(
                config,
                program_id=args.program,
                manifest_path=args.manifest,
                output_dir=args.output_dir,
            )
            print(f"Rendered {len(pages)} page(s) into {args.output_dir}")
            return 0
    except (
        AuditError,
        ConfigError,
        DownloadsError,
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
