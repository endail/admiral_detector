#!/usr/bin/env python3
"""Command-line interface for admiral_detector."""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from admiral_detector.config import (
    STDOUT_TARGET,
    SYSTEM_CONFIG_PATH,
    RuntimeConfig,
    build_scan_config,
    load_ini_config,
    validate_config_file,
)


# region Constants

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

KNOWN_SUBCOMMANDS = {"scan", "daemon", "strategies", "check-config"}
HELP_FLAGS = {"-h", "--help"}
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

# endregion


# region Logging & Output Helpers

def _configure_logging(config: RuntimeConfig, verbosity: int, quiet: bool, daemon_mode: bool) -> None:
    """Initialise console (stderr) or daemon file logging."""

    if(quiet):
        level = logging.ERROR
    elif(verbosity > 0):
        level = logging.DEBUG
    else:
        level = logging.INFO

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if(daemon_mode and config.log_dir is not None):
        config.log_dir.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(config.log_dir / "admiral_detector.log", encoding="utf-8"))

    logging.basicConfig(level=level, format=LOG_FORMAT, handlers=handlers, force=True)


def _write_results(payload: dict[str, Any], output_path: str) -> None:
    """Serialise scan payload to stdout or atomically to a target file."""

    serialised = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if(output_path == STDOUT_TARGET):
        sys.stdout.write(serialised)
        sys.stdout.flush()
        return

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(f"{destination.suffix}.tmp.{os.getpid()}")
    temp_path.write_text(serialised, encoding="utf-8")
    temp_path.replace(destination)


def _run_post_hooks(post_script_dir: Path | None, output_path: str) -> None:
    """Execute executable hook scripts in post_script_dir sequentially."""

    if(post_script_dir is None or not post_script_dir.is_dir()):
        return

    logger = logging.getLogger("admiral_detector.hooks")

    for script in sorted(post_script_dir.iterdir()):
        if(not script.is_file() or not os.access(script, os.X_OK)):
            continue

        logger.info("Executing post-scan hook: %s", script)
        env = os.environ.copy()
        env["ADMIRAL_OUTPUT_FILE"] = output_path
        subprocess.run([str(script)], env=env, check=True)

# endregion


# region Pipeline Adapters

def _list_registered_strategies() -> list[dict[str, str]]:
    """Return available detection strategy metadata from the strategy package."""

    # TODO: Wire directly to your strategy registry (e.g. admiral_detector.strategies.REGISTRY)
    from admiral_detector import strategies

    if(hasattr(strategies, "list_strategies")):
        return strategies.list_strategies()

    return [
        {"name": "inline_script", "description": "Extracts Admiral domains from inline <script> blocks."},
        {"name": "obfuscation", "description": "Decodes obfuscated/encoded Admiral bootstrap payloads."},
        {"name": "external_script", "description": "Inspects external third-party script references."},
        {"name": "heuristics", "description": "Matches structural anti-adblock domain heuristics."},
    ]


def _execute_pipeline(config: RuntimeConfig) -> dict[str, Any]:
    """Invoke the core detection and RDAP verification pipeline."""

    # TODO: Wire directly to your existing scanner entry point (e.g. admiral_detector.scanner.run_scan)
    from admiral_detector import scanner

    return scanner.run_scan(config)

# endregion


# region Subcommand Handlers

def _handle_scan(args: argparse.Namespace) -> int:
    """Execute an interactive or ad-hoc scan."""

    cli_urls = [*(args.positional_urls or []), *(args.url or [])]

    try:
        config = build_scan_config(
            explicit_config=args.config,
            cli_urls=cli_urls,
            cli_strategies=args.strategy or [],
            output_path=args.output,
            no_rdap=args.no_rdap,
            no_cache=args.no_cache,
            proxy=args.proxy,
            run_hooks=args.run_hooks,
        )
    except (FileNotFoundError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if(not config.urls):
        print(
            "Error: No target URLs provided. Pass one or more URLs "
            "(e.g. `admiral-detector scan https://example.com`) or specify `-c <config>`.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    _configure_logging(config, verbosity=args.verbose, quiet=args.quiet, daemon_mode=False)
    results = _execute_pipeline(config)
    _write_results(results, config.output_path)

    if(config.run_hooks):
        _run_post_hooks(config.post_script_dir, config.output_path)

    return EXIT_SUCCESS


def _handle_daemon(args: argparse.Namespace) -> int:
    """Execute a production scheduled scan for systemd."""

    try:
        config = load_ini_config(Path(args.config).expanduser(), daemon_mode=True)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if(args.dry_run):
        config.output_path = STDOUT_TARGET
        config.run_hooks = False

    _configure_logging(config, verbosity=0, quiet=False, daemon_mode=not args.dry_run)
    results = _execute_pipeline(config)
    _write_results(results, config.output_path)

    if(config.run_hooks and not args.dry_run):
        _run_post_hooks(config.post_script_dir, config.output_path)

    return EXIT_SUCCESS


def _handle_strategies(args: argparse.Namespace) -> int:
    """Print available detection strategies."""

    items = _list_registered_strategies()

    if(args.json):
        print(json.dumps(items, indent=2))
        return EXIT_SUCCESS

    for item in items:
        print(f"{item['name']:<18} {item['description']}")

    return EXIT_SUCCESS


def _handle_check_config(args: argparse.Namespace) -> int:
    """Validate an INI configuration file and exit non-zero on error."""

    target = Path(args.config).expanduser() if(args.config) else SYSTEM_CONFIG_PATH
    errors = validate_config_file(target)

    if(errors):
        print(f"Configuration invalid ({target}):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return EXIT_ERROR

    print(f"Configuration OK: {target}")
    return EXIT_SUCCESS

# endregion


# region Argument Parser

def _normalise_argv(argv: list[str]) -> list[str]:
    """Default bare invocations with URLs or scan flags to the `scan` subcommand."""

    if(not argv):
        return ["scan"]

    first = argv[0]
    if(first in KNOWN_SUBCOMMANDS or first in HELP_FLAGS):
        return argv

    return ["scan", *argv]


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level subcommand parser."""

    parser = argparse.ArgumentParser(
        prog="admiral-detector",
        description="Detect and verify Admiral anti-adblock domains.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Run an interactive or ad-hoc scan.")
    scan_parser.add_argument("positional_urls", nargs="*", metavar="URL", help="Target publisher URL(s).")
    scan_parser.add_argument("-u", "--url", action="append", help="Target publisher URL (repeatable).")
    scan_parser.add_argument("-c", "--config", help="Load baseline settings from an INI config file.")
    scan_parser.add_argument("-s", "--strategy", action="append", help="Run specific strategy only (repeatable).")
    scan_parser.add_argument("-o", "--output", help="Write JSON to PATH instead of stdout ('-').")
    scan_parser.add_argument("--no-rdap", action="store_true", help="Skip RDAP registration lookups.")
    scan_parser.add_argument("--no-cache", action="store_true", help="Do not read or write the RDAP cache.")
    scan_parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL for this scan.")
    scan_parser.add_argument("--run-hooks", action="store_true", help="Execute post.d hooks after scanning.")
    scan_parser.add_argument("-v", "--verbose", action="count", default=0, help="Enable debug logging on stderr.")
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="Only emit errors on stderr.")
    scan_parser.set_defaults(func=_handle_scan)

    # daemon
    daemon_parser = subparsers.add_parser("daemon", help="Run the production systemd scan workflow.")
    daemon_parser.add_argument("-c", "--config", required=True, help="Path to production INI config file.")
    daemon_parser.add_argument("--dry-run", action="store_true", help="Print JSON to stdout without writing files or hooks.")
    daemon_parser.set_defaults(func=_handle_daemon)

    # strategies
    strategies_parser = subparsers.add_parser("strategies", help="List available detection strategies.")
    strategies_parser.add_argument("--json", action="store_true", help="Output strategy metadata as JSON.")
    strategies_parser.set_defaults(func=_handle_strategies)

    # check-config
    check_parser = subparsers.add_parser("check-config", help="Validate an INI configuration file.")
    check_parser.add_argument("-c", "--config", help=f"Config file path (default: {SYSTEM_CONFIG_PATH}).")
    check_parser.set_defaults(func=_handle_check_config)

    return parser


def main(argv: list[str] | None = None) -> int:
    raw_argv = sys.argv[1:] if(argv is None) else argv
    parser = build_parser()
    args = parser.parse_args(_normalise_argv(raw_argv))
    return args.func(args)


if(__name__ == "__main__"):
    raise SystemExit(main())

# endregion