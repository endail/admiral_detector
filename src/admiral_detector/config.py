#!/usr/bin/env python3
"""Configuration loading, precedence resolution, and validation for admiral_detector."""

from __future__ import annotations

import configparser
from dataclasses import dataclass, field
import os
from pathlib import Path
import re


# region Constants

SYSTEM_CONFIG_PATH = Path("/etc/admiral_detector/admiral_detector.conf")
USER_CONFIG_PATH = Path.home() / ".config" / "admiral_detector" / "admiral_detector.conf"
USER_CACHE_PATH = Path.home() / ".cache" / "admiral_detector" / "rdap_cache.json"
STDOUT_TARGET = "-"

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
DEFAULT_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_REDIRECTS = 5

# endregion


# region Data Models

@dataclass
class RuntimeConfig:
    """Resolved runtime settings for a single scan or daemon execution."""

    urls: list[str] = field(default_factory=list)
    strategies: list[str] = field(default_factory=list)
    ignore_patterns: list[re.Pattern[str]] = field(default_factory=list)
    output_path: str = STDOUT_TARGET
    log_dir: Path | None = None
    rdap_cache_path: Path | None = USER_CACHE_PATH
    post_script_dir: Path | None = None
    use_rdap: bool = True
    run_hooks: bool = False
    proxy: str | None = None
    user_agent: str = DEFAULT_USER_AGENT
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_redirects: int = DEFAULT_MAX_REDIRECTS
    source_config: Path | None = None

# endregion


# region Config Helpers

def _split_multiline(raw_value: str) -> list[str]:
    return [line.strip() for line in raw_value.splitlines() if(line.strip() and not line.strip().startswith("#"))]


def resolve_scan_config_path(explicit_path: str | None, cli_urls: list[str]) -> Path | None:
    """Resolve which config file (if any) should be loaded for `scan` mode."""

    if(explicit_path is not None):
        return Path(explicit_path).expanduser()

    # Ad-hoc URL scans skip /etc and ~/.config unless explicitly requested
    if(cli_urls):
        return None

    if(USER_CONFIG_PATH.is_file() and os.access(USER_CONFIG_PATH, os.R_OK)):
        return USER_CONFIG_PATH

    if(SYSTEM_CONFIG_PATH.is_file() and os.access(SYSTEM_CONFIG_PATH, os.R_OK)):
        return SYSTEM_CONFIG_PATH

    return None


def load_ini_config(config_path: Path, daemon_mode: bool = False) -> RuntimeConfig:
    """Parse an INI configuration file into a RuntimeConfig instance."""

    if(not config_path.is_file()):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    if(not os.access(config_path, os.R_OK)):
        raise PermissionError(f"Permission denied reading configuration file: {config_path}")

    parser = configparser.ConfigParser()
    parser.read(config_path, encoding="utf-8")

    urls = _split_multiline(parser.get("publishers", "urls", fallback=""))
    strategies = _split_multiline(parser.get("detection", "strategies", fallback=""))
    raw_ignores = _split_multiline(parser.get("ignore", "patterns", fallback=""))
    ignore_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in raw_ignores]

    raw_output = parser.get("output", "file", fallback=STDOUT_TARGET).strip()
    raw_log_dir = parser.get("logging", "directory", fallback="").strip()
    raw_cache = parser.get("rdap", "cache_file", fallback="").strip()
    raw_hooks = parser.get("hooks", "post_script_dir", fallback="").strip()
    raw_proxy = parser.get("network", "proxy", fallback="").strip()

    # Interactive `scan` defaults to stdout and disabled hooks even when reading /etc
    output_path = raw_output if(daemon_mode and raw_output) else STDOUT_TARGET
    log_dir = Path(raw_log_dir) if(daemon_mode and raw_log_dir) else None
    rdap_cache_path = Path(raw_cache) if(daemon_mode and raw_cache) else USER_CACHE_PATH
    post_script_dir = Path(raw_hooks) if(raw_hooks) else None

    return RuntimeConfig(
        urls=urls,
        strategies=strategies,
        ignore_patterns=ignore_patterns,
        output_path=output_path,
        log_dir=log_dir,
        rdap_cache_path=rdap_cache_path,
        post_script_dir=post_script_dir,
        use_rdap=parser.getboolean("rdap", "enabled", fallback=True),
        run_hooks=daemon_mode,
        proxy=raw_proxy or None,
        user_agent=parser.get("network", "user_agent", fallback=DEFAULT_USER_AGENT).strip(),
        timeout_seconds=parser.getfloat("network", "timeout", fallback=DEFAULT_TIMEOUT_SECONDS),
        max_redirects=parser.getint("network", "max_redirects", fallback=DEFAULT_MAX_REDIRECTS),
        source_config=config_path,
    )


def build_scan_config(
    explicit_config: str | None,
    cli_urls: list[str],
    cli_strategies: list[str],
    output_path: str | None,
    no_rdap: bool,
    no_cache: bool,
    proxy: str | None,
    run_hooks: bool,
) -> RuntimeConfig:
    """Build a merged RuntimeConfig for interactive `scan` runs."""

    resolved_path = resolve_scan_config_path(explicit_config, cli_urls)
    config = load_ini_config(resolved_path, daemon_mode=False) if(resolved_path) else RuntimeConfig()

    if(cli_urls):
        config.urls = cli_urls

    if(cli_strategies):
        config.strategies = cli_strategies

    if(output_path is not None):
        config.output_path = output_path

    if(no_rdap):
        config.use_rdap = False

    if(no_cache):
        config.rdap_cache_path = None

    if(proxy is not None):
        config.proxy = proxy

    if(run_hooks):
        config.run_hooks = True

    return config


def validate_config_file(config_path: Path) -> list[str]:
    """Validate an INI configuration file and return a list of human-readable errors."""

    errors: list[str] = []

    if(not config_path.is_file()):
        return [f"Configuration file does not exist: {config_path}"]

    if(not os.access(config_path, os.R_OK)):
        return [f"Configuration file is not readable: {config_path}"]

    parser = configparser.ConfigParser()

    try:
        parser.read(config_path, encoding="utf-8")
    except configparser.Error as exc:
        return [f"INI syntax error: {exc}"]

    urls = _split_multiline(parser.get("publishers", "urls", fallback=""))
    if(not urls):
        errors.append("No target URLs configured under [publishers] -> urls.")

    for line_num, pattern in enumerate(_split_multiline(parser.get("ignore", "patterns", fallback="")), start=1):
        try:
            re.compile(pattern)
        except re.error as exc:
            errors.append(f"Invalid ignore regex at entry {line_num} ({pattern!r}): {exc}")

    output_file = parser.get("output", "file", fallback="").strip()
    if(output_file and output_file != STDOUT_TARGET):
        parent = Path(output_file).parent
        if(not parent.exists()):
            errors.append(f"Output parent directory does not exist: {parent}")
        elif(not os.access(parent, os.W_OK)):
            errors.append(f"Output parent directory is not writable: {parent}")

    log_dir = parser.get("logging", "directory", fallback="").strip()
    if(log_dir):
        log_path = Path(log_dir)
        if(not log_path.exists()):
            errors.append(f"Log directory does not exist: {log_path}")
        elif(not os.access(log_path, os.W_OK)):
            errors.append(f"Log directory is not writable: {log_path}")

    return errors

# endregion