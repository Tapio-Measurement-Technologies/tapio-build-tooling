"""Command-line interface."""

from __future__ import annotations

import argparse
from datetime import datetime
import os
from pathlib import Path
import shlex
import sys
import tempfile

from tapio_build_tools.archive import ArchiveError
from tapio_build_tools.archive.publish import names as archive_names
from tapio_build_tools.archive.publish import publish_archive
from tapio_build_tools.config import ConfigError, load_config
from tapio_build_tools.cooldown import CooldownError, cutoff, timestamp
from tapio_build_tools.downloads import DownloadsError
from tapio_build_tools.downloads.publish import (
    publish_downloads,
    publish_notes,
    publish_root_index,
    render_only,
)
from tapio_build_tools.ecosystems.node.audit import AuditError as NodeAuditError
from tapio_build_tools.ecosystems.node.audit import audit as audit_node
from tapio_build_tools.ecosystems.node.cooldown import check as check_node_cooldown
from tapio_build_tools.ecosystems.node.sbom import SbomError as NodeSbomError
from tapio_build_tools.ecosystems.node.sbom import generate_sbom as generate_node_sbom
from tapio_build_tools.ecosystems.python.audit import AuditError, audit
from tapio_build_tools.ecosystems.python.cooldown import check as check_python_cooldown
from tapio_build_tools.ecosystems.python.requirements import (
    RequirementsError,
    compile_requirements,
)
from tapio_build_tools.ecosystems.python.sbom import SbomError, generate_sbom
from tapio_build_tools.signing import SigningError
from tapio_build_tools.signing.keep import keep_module
from tapio_build_tools.signing.provision import Canary, Request, provision
from tapio_build_tools.signing.sign import sign_module


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
    compile_parser.add_argument(
        "--no-cooldown",
        action="store_true",
        help="ignore the configured cooldown, to take a release younger than it",
    )

    python_cooldown = python_commands.add_parser(
        "cooldown", help="check the ages of the releases a lock pins"
    )
    python_cooldown.add_argument("--group", required=True, help="configured requirement group")
    python_cooldown.add_argument(
        "--days", type=int, help="cooldown to check, overriding the configured one"
    )

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
    node_cooldown = node_commands.add_parser(
        "cooldown", help="check the ages of the releases the package lock pins"
    )
    node_cooldown.add_argument(
        "--days", type=int, help="cooldown to check, overriding the configured one"
    )
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

    archive = commands.add_parser("archive", help="private build archive operations")
    archive_commands = archive.add_subparsers(dest="archive_command", required=True)
    release_tag_help = "archive this run as a release of TAG; a tag push is a release of its own tag"
    names = archive_commands.add_parser("names", help="print this build's archive ID, release tag and builder image")
    names.add_argument("--release-tag", help=release_tag_help)
    archive_publish = archive_commands.add_parser("publish", help="bundle the prepared files and upload them to the archive bucket")
    archive_publish.add_argument("--release-tag", help=release_tag_help)
    archive_publish.add_argument("--builder-image", help="image the build ran in; recorded, and kept with a release")
    archive_publish.add_argument("--bucket", help="S3 bucket name; without one the archive is only written locally")
    archive_publish.add_argument("--output-dir", type=Path, help="where the archive is written; a new temporary directory by default")
    archive_publish.add_argument("--retention-days", type=int, help="lock every upload in governance mode for this many days")
    archive_publish.add_argument("--dry-run", action="store_true", help="write the archive and list the uploads without uploading")
    archive_publish.add_argument("--commit", help="source commit SHA")
    archive_publish.add_argument("--aws-region", help="region passed to the aws CLI")

    signing = commands.add_parser("signing", help="module signing with a key in Azure Key Vault")
    signing_commands = signing.add_subparsers(dest="signing_command", required=True)
    builder_help = ("the product's builder command line, answering manifest, digest, pack "
                    "and verify; see README")
    sign = signing_commands.add_parser("sign", help="sign one module, verify it, and record it")
    sign.add_argument("--builder", required=True, help=builder_help)
    sign.add_argument("--source", required=True, type=Path, help="the module's source directory")
    sign.add_argument("--output", required=True, type=Path, help="the signed file to write")
    sign.add_argument("--vault", required=True, help="Key Vault name")
    sign.add_argument("--key-name", required=True, help="the key's name in the vault")
    sign.add_argument("--key-id", help="the name the product pins the key by; the key name by default")
    sign.add_argument("--expect-id", help="fail unless the signed module verifies as this id")
    sign.add_argument("--created", help="ISO-8601 timestamp for the manifest, for a reproducible build")
    sign.add_argument("--record", type=Path, help="write the record of what was signed here, as JSON")
    sign.add_argument("--summary", type=Path, help="append the record as Markdown here, e.g. $GITHUB_STEP_SUMMARY")

    keep = signing_commands.add_parser(
        "keep", help="keep signed files and their record as the module version's pre-release")
    keep.add_argument("files", nargs="+", type=Path, help="the signed file(s) to keep")
    keep.add_argument("--record", required=True, type=Path, help="the record `signing sign` wrote")
    keep.add_argument("--tag-prefix", required=True,
                      help="tags are <prefix>/<id>/v<version>, e.g. postprocessor")
    keep.add_argument("--kind", required=True,
                      help="what the product calls a module, for the release title")
    keep.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""),
                      help="owner/name; $GITHUB_REPOSITORY by default")
    keep.add_argument("--target", default=os.environ.get("GITHUB_SHA", ""),
                      help="the commit to tag; $GITHUB_SHA by default")

    provision_parser = signing_commands.add_parser(
        "provision", help="set up one product's keys and signing identity; changes nothing that is already right")
    provision_parser.add_argument("--subscription", required=True, help="Azure subscription ID")
    provision_parser.add_argument("--resource-group", required=True)
    provision_parser.add_argument("--location", required=True, help="Azure region, for anything created")
    provision_parser.add_argument("--vault", required=True, help="Key Vault name, shared by every product")
    provision_parser.add_argument("--product", required=True, help="names the keys and the identity: [a-z0-9-]")
    provision_parser.add_argument("--repository", required=True, help="owner/name of the repository that signs")
    reviewing = provision_parser.add_mutually_exclusive_group(required=True)
    reviewing.add_argument("--reviewer", action="append",
                           help="GitHub login who approves signing runs; repeat for more")
    reviewing.add_argument("--no-reviewer", action="store_true",
                           help="no approval: anyone who can push to the branch can sign")
    provision_parser.add_argument("--environment", default="module-signing", help="GitHub environment that may sign")
    provision_parser.add_argument("--branch", default="main", help="the one branch the environment allows")
    provision_parser.add_argument("--generation", help="year in the key names; the current year by default")
    provision_parser.add_argument("--canary-builder", help=f"sign a canary per key with this builder; {builder_help}")
    provision_parser.add_argument("--canary-source", type=Path, help="the canary module's source directory")
    provision_parser.add_argument("--canary-dir", type=Path,
                                  help="where <key><extension> canaries are written")
    provision_parser.add_argument("--canary-extension", default=".tpp",
                                  help="the product's signed-file extension, with its dot; .tpp by default")
    provision_parser.add_argument("--canary-created", help="ISO-8601 timestamp for the canary manifests")
    provision_parser.add_argument("--keep-admin", action="store_true",
                                  help="keep the signed-in user's Key Vault Crypto Officer role afterwards")
    provision_parser.add_argument("--no-purge-protection", action="store_true",
                                  help="create the vault without purge protection, to try a setup out; "
                                       "a later run without this turns it on, for good")
    provision_parser.add_argument("--dry-run", action="store_true",
                                  help="look everything up and print each change instead of making it")
    return parser


def _window(
    parser: argparse.ArgumentParser, days: int | None, configured: int | None
) -> datetime | None:
    """The moment a pinned release has to predate, or None when none is set."""
    chosen = days if days is not None else configured
    if chosen is None:
        return None
    if not 1 <= chosen <= 365:
        parser.error("--days must be a whole number of days from 1 to 365")
    return cutoff(chosen)


def _signing(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    """The signing commands, which need no build-tooling.toml."""
    if args.signing_command == "sign":
        record = sign_module(
            builder=shlex.split(args.builder),
            source=args.source,
            output=args.output,
            vault=args.vault,
            key_name=args.key_name,
            key_id=args.key_id,
            expect_id=args.expect_id,
            created=args.created,
        )
        if args.record:
            args.record.parent.mkdir(parents=True, exist_ok=True)
            args.record.write_text(record.to_json(), encoding="utf-8")
        if args.summary:
            with args.summary.open("a", encoding="utf-8") as summary:
                summary.write(record.summary())
        print(record.to_json(), end="")
        return 0
    if args.signing_command == "keep":
        kept = keep_module(record_path=args.record, files=args.files, tag_prefix=args.tag_prefix,
                           kind=args.kind, repository=args.repository, target=args.target)
        if kept.created:
            print(f"Kept as {kept.tag}.")
        else:
            print(f"{kept.tag} is already issued with this content; nothing to keep.")
        return 0
    if args.signing_command == "provision":
        canary_options = (args.canary_builder, args.canary_source, args.canary_dir)
        if any(canary_options) and not all(canary_options):
            parser.error("--canary-builder, --canary-source and --canary-dir go together")
        canary = None
        if args.canary_builder:
            canary = Canary(builder=tuple(shlex.split(args.canary_builder)), source=args.canary_source,
                            directory=args.canary_dir, created=args.canary_created,
                            extension=args.canary_extension)
        options = {}
        if args.generation:
            options["generation"] = args.generation
        request = Request(
            subscription=args.subscription,
            resource_group=args.resource_group,
            location=args.location,
            vault=args.vault,
            product=args.product,
            repository=args.repository,
            reviewers=tuple(args.reviewer or ()),
            require_reviewer=not args.no_reviewer,
            environment=args.environment,
            branch=args.branch,
            canary=canary,
            keep_admin=args.keep_admin,
            purge_protection=not args.no_purge_protection,
            **options,
        )
        result = provision(request, dry_run=args.dry_run)
        verb = "Would make" if args.dry_run else "Made"
        print(f"{verb} {len(result.changes)} change(s).")
        print("Pin these in the product's key table:")
        print(result.trusted_keys(), end="")
        for canary_file in result.canaries:
            print(f"Signed canary: {canary_file}")
        return 0
    parser.error("unsupported command")
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "signing":
        try:
            return _signing(parser, args)
        except SigningError as exc:
            print(f"tapio-build: error: {exc}", file=sys.stderr)
            return 2
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
                cooldown=not args.no_cooldown,
            )
            for result in results:
                print(f"{result.group}: {result.status}")
            return 0
        if args.command == "python" and args.python_command == "cooldown":
            moment = _window(parser, args.days, config.require_python().cooldown_days)
            if moment is None:
                print(f"{args.group}: no cooldown configured")
                return 0
            pinned = check_python_cooldown(config, args.group, moment)
            print(f"{args.group}: {len(pinned)} release(s), none newer than {timestamp(moment)}")
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
        if args.command == "node" and args.node_command == "cooldown":
            moment = _window(parser, args.days, config.require_node().cooldown_days)
            if moment is None:
                print("package-lock.json: no cooldown configured")
                return 0
            pinned = check_node_cooldown(config, moment)
            print(f"package-lock.json: {len(pinned)} release(s), none newer than {timestamp(moment)}")
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
        if args.command == "archive" and args.archive_command == "names":
            print(archive_names(config, release_tag=args.release_tag).lines(), end="")
            return 0
        if args.command == "archive" and args.archive_command == "publish":
            output_dir = args.output_dir or Path(tempfile.mkdtemp(prefix="tapio-archive-"))
            summary = publish_archive(
                config,
                output_dir=output_dir,
                release_tag=args.release_tag,
                builder_image=args.builder_image,
                bucket=args.bucket,
                aws_region=args.aws_region,
                retention_days=args.retention_days,
                dry_run=args.dry_run,
                commit=args.commit,
            )
            if not args.bucket:
                print(f"Archived {summary.prefix} without uploading; no bucket given")
            else:
                verb = "Would upload" if args.dry_run else "Uploaded"
                print(f"{verb} {summary.prefix}: {len(summary.files)} file(s)")
            print(f"Archive and summary: {output_dir}")
            return 0
    except (
        ArchiveError,
        AuditError,
        ConfigError,
        CooldownError,
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
