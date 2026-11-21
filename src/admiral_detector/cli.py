import argparse
import datetime
import json
import logging
import re
import sys
import time
from typing import Any, Dict, List, Optional, Set

from . import __version__ as FALLBACK_VERSION
from .config import (
    STDOUT_TARGET,
    STRATEGY_DESCRIPTIONS,
    SYSTEM_CONFIG_PATH,
    TargetSite,
    build_scan_targets_and_opts,
    load_config,
    parse_cli_strategies,
    validate_config_file,
)
from .logger import setup_logger
from .network import create_http_client, use_dns
from .output import run_post_scripts, write_json_output
from .rdap import RDAPCache, verify_domain_rdap
from .strategies.factory import get_strategy

try:
    from importlib.metadata import version

    PKG_VERSION = version("admiral_detector")
except Exception:
    PKG_VERSION = FALLBACK_VERSION


# region Constants

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

KNOWN_SUBCOMMANDS = {"scan", "daemon", "strategies", "check-config"}
PASSTHROUGH_FLAGS = {"-h", "--help", "-V", "--version"}

# endregion


# region Detection Pipeline

def is_ignored(domain: str, ignore_domains: Set[str], ignore_regexes: List[re.Pattern]) -> bool:
    if(domain in ignore_domains):
        return True
    for regex in ignore_regexes:
        if(regex.search(domain)):
            return True
    return False


def run_detection_pipeline(
    targets: List[TargetSite],
    global_opts: Dict[str, Any],
    logger: logging.Logger,
) -> Dict[str, Any]:
    """Execute HTTP fetching, strategy extraction, and RDAP verification for all targets."""

    start_time = time.time()
    logger.info(f"Starting admiral_detector v{PKG_VERSION}")

    for cfg_warn in global_opts.get("config_warnings", []):
        logger.warning(cfg_warn)
    for cfg_err in global_opts.get("config_errors", []):
        logger.error(cfg_err)

    cache_file = global_opts.get("rdap_cache_file")
    rdap_cache: Optional[RDAPCache] = None
    if(cache_file):
        rdap_cache = RDAPCache(
            cache_file=cache_file,
            ttl_seconds=global_opts["rdap_cache_ttl_seconds"],
        )

    results = []
    total_unique_domains: Set[str] = set()

    for target in targets:
        for warn in target.warnings:
            logger.warning(warn)

        strategies_label = ", ".join(target.strategies)
        logger.info(
            f"Scanning: {target.url} [Strategies: {strategies_label}, Profile: {target.profile or 'none'}]"
        )
        target_result: Dict[str, Any] = {
            "publisher": target.name,
            "profile": target.profile,
            "initial_url": target.url,
            "strategies": target.strategies,
            "date_detected": datetime.datetime.now().isoformat(),
            "network": {
                "initial_url": target.url,
                "final_url": None,
                "redirect_chain": [],
                "http_status": None,
                "response_time_ms": None,
                "proxy_used": target.proxy,
                "dns_used": target.dns,
                "tls_verified": not target.allow_insecure,
                "headers_sent": target.headers,
            },
            "extracted_domains": [],
            "rdap_rejected_domains": [],
            "ignored_domains": [],
            "error": None,
        }

        try:
            with use_dns(target.dns), create_http_client(
                timeout_seconds=target.timeout_seconds,
                max_redirects=target.max_redirects,
                proxy=target.proxy,
                verify_ssl=not target.allow_insecure,
            ) as client:
                resp = client.get(target.url, headers=target.headers)
                html_body = resp.text
                final_url = str(resp.url)
                all_urls = [str(r.url) for r in resp.history] + [final_url]
                redirect_chain = all_urls[1:]

                target_result["network"].update(
                    {
                        "final_url": final_url,
                        "redirect_chain": redirect_chain,
                        "http_status": resp.status_code,
                        "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                    }
                )

                logger.debug(
                    f"HTTP {resp.status_code} received from final URL: {final_url} "
                    f"(redirects: {len(redirect_chain)})"
                )

                merged_extractions: Dict[str, Dict[str, Any]] = {}
                for strategy_name in target.strategies:
                    strategy = get_strategy(strategy_name)
                    extractions = strategy.extract(html_body, final_url)
                    for domain, snippet in sorted(extractions):
                        if(domain not in merged_extractions):
                            merged_extractions[domain] = {
                                "snippet": snippet,
                                "matched_strategies": [strategy_name],
                            }
                        elif(strategy_name not in merged_extractions[domain]["matched_strategies"]):
                            merged_extractions[domain]["matched_strategies"].append(strategy_name)

                for domain in sorted(merged_extractions.keys()):
                    entry_info = merged_extractions[domain]
                    snippet = entry_info["snippet"]
                    matched_strategies = entry_info["matched_strategies"]

                    if(is_ignored(domain, target.ignore_domains, target.ignore_regexes)):
                        logger.debug(f"Ignored: {domain} (matched ignore list)")
                        target_result["ignored_domains"].append(domain)
                        continue

                    if(target.verify_rdap):
                        active_cache = rdap_cache if(rdap_cache is not None) else _EphemeralRDAPCache()
                        is_admiral, rdap_details = verify_domain_rdap(
                            domain=domain,
                            cache=active_cache,
                            rdap_domain=target.rdap_domain,
                            timeout=target.timeout_seconds,
                            max_redirects=target.max_redirects,
                            proxy=target.proxy,
                            dns=target.dns,
                        )
                        if(is_admiral):
                            total_unique_domains.add(domain)
                            logger.info(f"Detected [RDAP Verified]: {domain}")
                            logger.debug(f"Context: {snippet}")
                            target_result["extracted_domains"].append(
                                {
                                    "domain": domain,
                                    "matched_strategies": matched_strategies,
                                    "context_snippet": snippet,
                                    "rdap_verified": True,
                                    "rdap_details": rdap_details,
                                }
                            )
                        else:
                            logger.debug(f"RDAP Rejected: {domain}")
                            target_result["rdap_rejected_domains"].append(
                                {
                                    "domain": domain,
                                    "matched_strategies": matched_strategies,
                                    "context_snippet": snippet,
                                    "rdap_verified": False,
                                    "rdap_details": rdap_details,
                                }
                            )
                    else:
                        total_unique_domains.add(domain)
                        logger.info(f"Detected: {domain}")
                        logger.debug(f"Context: {snippet}")
                        target_result["extracted_domains"].append(
                            {
                                "domain": domain,
                                "matched_strategies": matched_strategies,
                                "context_snippet": snippet,
                                "rdap_verified": None,
                                "rdap_details": None,
                            }
                        )

        except Exception as error:
            logger.error(f"Error fetching {target.url}: {error}")
            target_result["error"] = str(error)

        results.append(target_result)

    duration = time.time() - start_time
    return {
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": PKG_VERSION,
            "duration_seconds": round(duration, 2),
            "total_publishers_scanned": len(targets),
            "unique_domains": sorted(list(total_unique_domains)),
        },
        "results": results,
    }


class _EphemeralRDAPCache(RDAPCache):
    """In-memory no-op RDAP cache used when --no-cache is specified."""

    def __init__(self):
        self.ttl_seconds = 0
        self.cache_file = ""
        self.cache = {}

    def get(self, domain: str) -> None:
        return None

    def set(self, domain: str, is_admiral: bool, details: Dict[str, Any]) -> None:
        return None

# endregion


# region Subcommand Handlers

def _resolve_cli_log_level(base_level: str, verbose: int, quiet: bool) -> str:
    if(quiet):
        return "ERROR"
    if(verbose > 0):
        return "DEBUG"
    return base_level


def _handle_scan(args: argparse.Namespace) -> int:
    cli_urls = [*(args.positional_urls or []), *(args.url or [])]

    try:
        cli_strategies = parse_cli_strategies(args.strategy or [])
        targets, global_opts = build_scan_targets_and_opts(
            explicit_config=args.config,
            cli_urls=cli_urls,
            cli_strategies=cli_strategies,
            profile=args.profile,
            output_file=args.output,
            verify_rdap=args.rdap,
            no_cache=args.no_cache,
            proxy=args.proxy,
            dns_server=args.dns,
            allow_insecure=args.allow_insecure,
            run_hooks=args.run_hooks,
        )
    except (FileNotFoundError, PermissionError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if(not targets):
        print(
            "Error: No target URLs provided. Pass one or more URLs "
            "(e.g. `admiral-detector scan https://www.news.com.au`) or specify `-c <config>`.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    log_level = _resolve_cli_log_level(global_opts["log_level"], args.verbose, args.quiet)
    logger = setup_logger(log_level, global_opts["log_file"], stream=sys.stderr)

    json_payload = run_detection_pipeline(targets, global_opts, logger)

    if(global_opts["output_file"]):
        write_json_output(json_payload, global_opts["output_file"])
    if(args.run_hooks and global_opts["post_script_dir"]):
        run_post_scripts(global_opts["post_script_dir"], global_opts["output_file"])

    return EXIT_SUCCESS


def _handle_daemon(args: argparse.Namespace) -> int:
    try:
        targets, global_opts = load_config(args.config)
    except (FileNotFoundError, PermissionError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    if(args.dry_run):
        global_opts["output_file"] = STDOUT_TARGET
        global_opts["post_script_dir"] = None
        global_opts["log_file"] = None

    logger = setup_logger(global_opts["log_level"], global_opts["log_file"], stream=sys.stderr)
    json_payload = run_detection_pipeline(targets, global_opts, logger)

    if(global_opts["output_file"]):
        write_json_output(json_payload, global_opts["output_file"])
    if(global_opts["post_script_dir"] and not args.dry_run):
        run_post_scripts(global_opts["post_script_dir"], global_opts["output_file"])

    return EXIT_SUCCESS


def _handle_strategies(args: argparse.Namespace) -> int:
    items = [
        {"name": name, "description": desc}
        for name, desc in STRATEGY_DESCRIPTIONS.items()
    ]

    if(args.json):
        print(json.dumps(items, indent=2))
        return EXIT_SUCCESS

    for item in items:
        print(f"{item['name']:<20} {item['description']}")

    return EXIT_SUCCESS


def _handle_check_config(args: argparse.Namespace) -> int:
    target_path = args.config or SYSTEM_CONFIG_PATH
    errors, warnings = validate_config_file(target_path)

    for warn in warnings:
        print(f"Warning: {warn}", file=sys.stderr)

    if(errors):
        print(f"Configuration invalid ({target_path}):", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return EXIT_ERROR

    targets, _ = load_config(target_path)
    print(f"Configuration OK: {target_path} ({len(targets)} target(s) configured)")
    return EXIT_SUCCESS

# endregion


# region Argument Parser

def _normalise_argv(argv: List[str]) -> List[str]:
    """Default bare invocations with URLs or scan flags to the `scan` subcommand."""

    if(not argv):
        return ["scan"]

    first = argv[0]
    if(first in KNOWN_SUBCOMMANDS or first in PASSTHROUGH_FLAGS):
        return argv

    return ["scan", *argv]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="admiral-detector",
        description="Admiral/Leven Labs Proactive Domain Detector",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"admiral_detector {PKG_VERSION}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Run an interactive or ad-hoc scan.")
    scan_parser.add_argument("positional_urls", nargs="*", metavar="URL", help="Target publisher URL(s).")
    scan_parser.add_argument("-u", "--url", action="append", help="Target publisher URL (repeatable).")
    scan_parser.add_argument("-c", "--config", help="Load baseline settings from an INI config file.")
    scan_parser.add_argument("-s", "--strategy", action="append", help="Strategy name(s) (repeatable or CSV).")
    scan_parser.add_argument("-p", "--profile", help="Named [profile:<name>] from --config to apply.")
    scan_parser.add_argument("-o", "--output", help="Write JSON to PATH instead of stdout ('-').")
    scan_parser.add_argument("--rdap", action=argparse.BooleanOptionalAction, default=None, help="Enable/disable RDAP verification.")
    scan_parser.add_argument("--no-cache", action="store_true", help="Bypass reading/writing the RDAP cache.")
    scan_parser.add_argument("--proxy", help="HTTP/SOCKS proxy URL for this scan.")
    scan_parser.add_argument("--dns", help="Custom DNS resolver IP (e.g. 1.1.1.1) for this scan.")
    scan_parser.add_argument("--allow-insecure", action="store_true", help="Permit http:// and disable TLS verification.")
    scan_parser.add_argument("--run-hooks", action="store_true", help="Execute post_script_dir hooks after scanning.")
    scan_parser.add_argument("-v", "--verbose", action="count", default=0, help="Enable DEBUG logging on stderr.")
    scan_parser.add_argument("-q", "--quiet", action="store_true", help="Only emit ERROR logs on stderr.")
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


def main(argv: Optional[List[str]] = None) -> int:
    raw_argv = sys.argv[1:] if(argv is None) else argv
    parser = build_parser()
    args = parser.parse_args(_normalise_argv(raw_argv))
    return args.func(args)


if(__name__ == "__main__"):
    raise SystemExit(main())

# endregion