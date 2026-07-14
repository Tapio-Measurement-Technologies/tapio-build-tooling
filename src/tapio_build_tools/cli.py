"""Command-line interface."""

from __future__ import annotations

import argparse
import sys

from tapio_build_tools.config import ConfigError, load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tapio-build")
    parser.add_argument("--project", default=".", help="consumer project root")
    parser.add_argument("--config", default="build-tooling.toml", help="configuration path")
    commands = parser.add_subparsers(dest="command", required=True)
    config = commands.add_parser("config", help="configuration operations")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    config_commands.add_parser("validate", help="validate configuration and referenced files")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.project, args.config)
        if args.command == "config" and args.config_command == "validate":
            print(f"Valid: {config.path}")
            return 0
    except ConfigError as exc:
        print(f"tapio-build: error: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2

