"""Command-line interface."""

from __future__ import annotations

import argparse
import sys

from tapio_build_tools.config import ConfigError, load_config
from tapio_build_tools.ecosystems.python.requirements import (
    RequirementsError,
    compile_requirements,
)


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
    except (ConfigError, RequirementsError) as exc:
        print(f"tapio-build: error: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2
