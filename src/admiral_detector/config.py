import configparser
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse


# region Constants

DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
DEFAULT_STRATEGY = "inline_script"
DEFAULT_RDAP_DOMAIN = "rdap.org"
DEFAULT_OUTPUT_FILE = "/run/admiral_detector/detected_domains.json"
DEFAULT_RDAP_CACHE_FILE = "/var/lib/admiral_detector/rdap_cache.json"
DEFAULT_RDAP_CACHE_TTL = 60 * 60 * 24 * 30
DEFAULT_TIMEOUT_SECONDS = 15
DEFAULT_MAX_REDIRECTS = 5
DEFAULT_LOG_LEVEL = "INFO"

SYSTEM_CONFIG_PATH = "/etc/admiral_detector/admiral_detector.conf"
USER_CONFIG_PATH = os.path.expanduser("~/.config/admiral_detector/admiral_detector.conf")
USER_CACHE_PATH = os.path.expanduser("~/.cache/admiral_detector/rdap_cache.json")
STDOUT_TARGET = "-"

STRATEGY_DESCRIPTIONS: Dict[str, str] = {
    "inline_script": "Inspects inline <script> blocks with Admiral loader markers.",
    "obfuscated_inline": "Decodes Base64 blobs inside inline <script> tags.",
    "external_script": "Extracts apex domains from <script src=\"...\"> tags.",
    "broad_heuristic": "Multi-pass URI-decodes full HTML and extracts third-party apex domains.",
    "all_domains": "Scans raw HTML for all third-party HTTP(S) apex domains.",
    "all_js_domains": "Extracts all third-party apex domains across any inline <script> tag.",
}

VALID_STRATEGIES = set(STRATEGY_DESCRIPTIONS.keys())

SCHEME_PREFIX_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")
HEADER_SPLIT_REGEX = re.compile(r"[-_]+")
REGEX_PREFIX = "regex:"
HEADER_PREFIX = "header_"
PUBLISHER_SECTION_PREFIX = "publisher:"
PROFILE_SECTION_PREFIX = "profile:"

# endregion


# region Data Models

class TargetSite:

    def __init__(
        self,
        name: str,
        url: str,
        strategies: List[str],
        profile: Optional[str],
        verify_rdap: bool,
        ignore_domains: Set[str],
        ignore_regexes: List[re.Pattern],
        rdap_domain: str,
        headers: Dict[str, str],
        timeout_seconds: int,
        max_redirects: int,
        proxy: Optional[str],
        dns: Optional[str],
        allow_insecure: bool,
        warnings: Optional[List[str]] = None,
    ):
        self.name = name
        self.url = url
        self.strategies = strategies
        self.profile = profile
        self.verify_rdap = verify_rdap
        self.ignore_domains = ignore_domains
        self.ignore_regexes = ignore_regexes
        self.rdap_domain = rdap_domain
        self.headers = headers
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.proxy = proxy
        self.dns = dns
        self.allow_insecure = allow_insecure
        self.warnings = warnings or []

# endregion


# region Parsing & URL Validation Helpers

def canonical_header_name(name: str) -> str:
    return "-".join(part.capitalize() for part in HEADER_SPLIT_REGEX.split(name.strip()) if(part))


def _set_header(headers: Dict[str, str], name: str, value: str) -> None:
    canonical_name = canonical_header_name(name)
    if(not canonical_name):
        return

    target_lower = canonical_name.lower()
    existing = [k for k in headers if(k.lower() == target_lower)]
    for k in existing:
        del headers[k]

    headers[canonical_name] = value


def _normalise_optional_str(value: Optional[str]) -> Optional[str]:
    if(value is None):
        return None
    stripped = value.strip()
    return stripped if(stripped) else None


def _parse_strategies(raw_strategy: str) -> Tuple[List[str], List[str]]:
    strategies: List[str] = []
    warnings: List[str] = []

    for item in raw_strategy.split(","):
        cleaned = item.strip()
        if(not cleaned):
            continue
        if(cleaned not in VALID_STRATEGIES):
            warnings.append(f"Unknown extraction strategy '{cleaned}' ignored.")
            continue
        if(cleaned not in strategies):
            strategies.append(cleaned)

    if(not strategies):
        warnings.append(f"No valid strategies specified; falling back to '{DEFAULT_STRATEGY}'.")
        strategies.append(DEFAULT_STRATEGY)

    return strategies, warnings


def parse_cli_strategies(raw_items: List[str]) -> List[str]:
    """Parse and strictly validate repeatable or comma-separated CLI strategy flags."""

    parsed: List[str] = []
    for raw_item in raw_items:
        for piece in raw_item.split(","):
            cleaned = piece.strip()
            if(not cleaned):
                continue
            if(cleaned not in VALID_STRATEGIES):
                valid_list = ", ".join(sorted(VALID_STRATEGIES))
                raise ValueError(f"Unknown strategy '{cleaned}'. Valid strategies: {valid_list}")
            if(cleaned not in parsed):
                parsed.append(cleaned)

    return parsed


def _parse_ignore_list(raw_string: str) -> Tuple[Set[str], List[re.Pattern], List[str]]:
    domains: Set[str] = set()
    regexes: List[re.Pattern] = []
    warnings: List[str] = []

    parts = [p.strip() for p in raw_string.split(",") if(p.strip())]
    for p in parts:
        if(p.startswith(REGEX_PREFIX)):
            pattern_str = p[len(REGEX_PREFIX):]
            try:
                regexes.append(re.compile(pattern_str))
            except re.error as e:
                warnings.append(f"Invalid regex '{pattern_str}' in ignore list: {e}")
        else:
            domains.add(p.lower())

    return domains, regexes, warnings


def validate_and_normalise_url(raw_url: str, allow_insecure: bool = False) -> Tuple[str, Optional[str]]:
    cleaned = raw_url.strip()
    if(not cleaned):
        raise ValueError("Empty URL provided.")

    if("://" not in cleaned):
        if(SCHEME_PREFIX_REGEX.match(cleaned)):
            scheme_prefix = cleaned.split(":", 1)[0].lower()
            raise ValueError(
                f"Unsupported URL protocol '{scheme_prefix}:' rejected for '{cleaned}'. "
                f"Only HTTPS (or HTTP with allow_insecure=true) is permitted."
            )
        cleaned = f"https://{cleaned}"

    parsed = urllib.parse.urlsplit(cleaned)
    scheme = parsed.scheme.lower()

    if(scheme == "https"):
        warning = None
    elif(scheme == "http"):
        if(not allow_insecure):
            raise ValueError(
                f"Insecure protocol 'http://' rejected for '{cleaned}'. "
                f"Set allow_insecure = true (or pass --allow-insecure) to permit plaintext HTTP."
            )
        warning = f"Insecure HTTP URL permitted via allow_insecure=true: {cleaned}"
    else:
        raise ValueError(
            f"Unsupported URL protocol '{scheme}://' rejected for '{cleaned}'. "
            f"Only HTTPS (or HTTP with allow_insecure=true) is permitted."
        )

    if(not parsed.hostname):
        raise ValueError(f"Invalid URL missing hostname: '{cleaned}'")

    _ = parsed.port
    return urllib.parse.urlunsplit(parsed), warning

# endregion


# region INI Loading & Precedence Resolution

def _read_ini_parser(config_path: str) -> configparser.ConfigParser:
    if(not os.path.exists(config_path)):
        raise FileNotFoundError(f"Config file missing: {config_path}")

    if(not os.access(config_path, os.R_OK)):
        raise PermissionError(f"Permission denied reading config file: {config_path}")

    config = configparser.ConfigParser(allow_no_value=True, delimiters=("=",))
    config.optionxform = str
    config.read(config_path, encoding="utf-8")
    return config


def _extract_profile_headers(
    config: configparser.ConfigParser,
    base_headers: Dict[str, str],
    profile_name: Optional[str],
    warnings: List[str],
) -> Dict[str, str]:
    headers = base_headers.copy()
    if(not profile_name):
        return headers

    profile_section = f"{PROFILE_SECTION_PREFIX}{profile_name}"
    if(config.has_section(profile_section)):
        for k, v in config.items(profile_section):
            if(k.lower().startswith(HEADER_PREFIX) and v is not None):
                _set_header(headers, k[len(HEADER_PREFIX):], v)
    else:
        warnings.append(f"Referenced profile '{profile_name}' does not exist in config.")

    return headers


def load_config(config_path: str) -> Tuple[List[TargetSite], Dict[str, Any]]:
    config = _read_ini_parser(config_path)

    config_warnings: List[str] = []
    config_errors: List[str] = []

    raw_default_strategy = config.get("defaults", "strategy", fallback=DEFAULT_STRATEGY)
    default_strategies, strategy_warnings = _parse_strategies(raw_default_strategy)
    config_warnings.extend(strategy_warnings)

    raw_default_ignore = config.get("defaults", "ignore_domains", fallback="")
    default_ignore_domains, default_ignore_regexes, ignore_warnings = _parse_ignore_list(raw_default_ignore)
    config_warnings.extend(ignore_warnings)

    default_headers: Dict[str, str] = {}
    _set_header(default_headers, "User-Agent", DEFAULT_USER_AGENT)

    if(config.has_section("defaults")):
        for k, v in config.items("defaults"):
            if(k.lower().startswith(HEADER_PREFIX) and v is not None):
                _set_header(default_headers, k[len(HEADER_PREFIX):], v)

    global_opts: Dict[str, Any] = {
        "output_file": _normalise_optional_str(
            config.get("general", "output_file", fallback=DEFAULT_OUTPUT_FILE)
        ),
        "post_script_dir": _normalise_optional_str(
            config.get("general", "post_script_dir", fallback=None)
        ),
        "default_strategies": default_strategies,
        "default_ignore_domains": default_ignore_domains,
        "default_ignore_regexes": default_ignore_regexes,
        "default_headers": default_headers,
        "verify_rdap": config.getboolean("rdap", "verify", fallback=False),
        "rdap_domain": config.get("rdap", "domain", fallback=DEFAULT_RDAP_DOMAIN).strip(),
        "rdap_cache_file": config.get("rdap", "cache_file", fallback=DEFAULT_RDAP_CACHE_FILE).strip(),
        "rdap_cache_ttl_seconds": config.getint("rdap", "cache_ttl_seconds", fallback=DEFAULT_RDAP_CACHE_TTL),
        "timeout_seconds": config.getint("network", "timeout_seconds", fallback=DEFAULT_TIMEOUT_SECONDS),
        "max_redirects": config.getint("network", "max_redirects", fallback=DEFAULT_MAX_REDIRECTS),
        "proxy": _normalise_optional_str(config.get("network", "proxy", fallback=None)),
        "dns": _normalise_optional_str(config.get("network", "dns", fallback=None)),
        "allow_insecure": config.getboolean("network", "allow_insecure", fallback=False),
        "log_level": config.get("logging", "level", fallback=DEFAULT_LOG_LEVEL).strip(),
        "log_file": _normalise_optional_str(config.get("logging", "file", fallback=None)),
        "config_warnings": config_warnings,
        "config_errors": config_errors,
        "_ini_parser": config,
    }

    targets: List[TargetSite] = []

    if(config.has_section("publishers")):
        for key, val in config.items("publishers"):
            if(val is not None and (val != "" or "?" in key)):
                raw_entry = f"{key}={val}"
            else:
                raw_entry = key

            raw_entry = raw_entry.strip()
            if(not raw_entry or raw_entry.startswith("#")):
                continue

            try:
                normalised_url, url_warning = validate_and_normalise_url(
                    raw_entry,
                    allow_insecure=global_opts["allow_insecure"],
                )
            except ValueError as err:
                config_errors.append(str(err))
                continue

            site_warnings = [url_warning] if(url_warning) else []
            targets.append(
                TargetSite(
                    name="publishers",
                    url=normalised_url,
                    strategies=list(default_strategies),
                    profile=None,
                    verify_rdap=global_opts["verify_rdap"],
                    ignore_domains=set(default_ignore_domains),
                    ignore_regexes=list(default_ignore_regexes),
                    rdap_domain=global_opts["rdap_domain"],
                    headers=default_headers.copy(),
                    timeout_seconds=global_opts["timeout_seconds"],
                    max_redirects=global_opts["max_redirects"],
                    proxy=global_opts["proxy"],
                    dns=global_opts["dns"],
                    allow_insecure=global_opts["allow_insecure"],
                    warnings=site_warnings,
                )
            )

    for section in config.sections():
        if(section.startswith(PUBLISHER_SECTION_PREFIX)):
            pub_name = section[len(PUBLISHER_SECTION_PREFIX):]
            if(not config.has_option(section, "url")):
                config_errors.append(f"Section [{section}] is missing required 'url' option.")
                continue

            raw_url = config.get(section, "url")
            site_warnings: List[str] = []

            if(config.has_option(section, "strategy")):
                raw_pub_strategy = config.get(section, "strategy") or ""
                site_strategies, pub_strat_warns = _parse_strategies(raw_pub_strategy)
                site_warnings.extend(pub_strat_warns)
            else:
                site_strategies = list(default_strategies)

            if(config.has_option(section, "verify_rdap")):
                verify = config.getboolean(section, "verify_rdap")
            elif(config.has_option(section, "verify")):
                verify = config.getboolean(section, "verify")
            else:
                verify = global_opts["verify_rdap"]

            rdap_domain = config.get(section, "rdap_domain", fallback=global_opts["rdap_domain"]).strip()
            timeout_seconds = config.getint(section, "timeout_seconds", fallback=global_opts["timeout_seconds"])
            max_redirects = config.getint(section, "max_redirects", fallback=global_opts["max_redirects"])

            if(config.has_option(section, "proxy")):
                proxy = _normalise_optional_str(config.get(section, "proxy"))
            else:
                proxy = global_opts["proxy"]

            if(config.has_option(section, "dns")):
                dns_server = _normalise_optional_str(config.get(section, "dns"))
            else:
                dns_server = global_opts["dns"]

            allow_insecure = config.getboolean(section, "allow_insecure", fallback=global_opts["allow_insecure"])

            try:
                normalised_url, url_warning = validate_and_normalise_url(
                    raw_url,
                    allow_insecure=allow_insecure,
                )
            except ValueError as err:
                config_errors.append(f"[{section}] {err}")
                continue

            if(url_warning):
                site_warnings.append(url_warning)

            profile_used: Optional[str] = None
            if(config.has_option(section, "profile")):
                raw_profile = config.get(section, "profile")
                if(raw_profile and raw_profile.strip()):
                    profile_used = raw_profile.strip()

            site_headers = _extract_profile_headers(config, default_headers, profile_used, site_warnings)

            for k, v in config.items(section):
                if(k.lower().startswith(HEADER_PREFIX) and v is not None):
                    _set_header(site_headers, k[len(HEADER_PREFIX):], v)

            if(config.has_option(section, "ignore_domains")):
                raw_ignore = config.get(section, "ignore_domains") or ""
                site_ignore_doms, site_ignore_regs, local_ignore_warns = _parse_ignore_list(raw_ignore)
                site_warnings.extend(local_ignore_warns)
            elif(config.has_option(section, "default_ignore_domains")):
                raw_ignore = config.get(section, "default_ignore_domains") or ""
                site_ignore_doms, site_ignore_regs, local_ignore_warns = _parse_ignore_list(raw_ignore)
                site_warnings.extend(local_ignore_warns)
            else:
                site_ignore_doms = set(default_ignore_domains)
                site_ignore_regs = list(default_ignore_regexes)

            targets.append(
                TargetSite(
                    name=pub_name,
                    url=normalised_url,
                    strategies=site_strategies,
                    profile=profile_used,
                    verify_rdap=verify,
                    ignore_domains=site_ignore_doms,
                    ignore_regexes=site_ignore_regs,
                    rdap_domain=rdap_domain,
                    headers=site_headers,
                    timeout_seconds=timeout_seconds,
                    max_redirects=max_redirects,
                    proxy=proxy,
                    dns=dns_server,
                    allow_insecure=allow_insecure,
                    warnings=site_warnings,
                )
            )

    return targets, global_opts


def _build_default_global_opts() -> Dict[str, Any]:
    default_headers: Dict[str, str] = {}
    _set_header(default_headers, "User-Agent", DEFAULT_USER_AGENT)

    return {
        "output_file": STDOUT_TARGET,
        "post_script_dir": None,
        "default_strategies": [DEFAULT_STRATEGY],
        "default_ignore_domains": set(),
        "default_ignore_regexes": [],
        "default_headers": default_headers,
        "verify_rdap": True,
        "rdap_domain": DEFAULT_RDAP_DOMAIN,
        "rdap_cache_file": USER_CACHE_PATH,
        "rdap_cache_ttl_seconds": DEFAULT_RDAP_CACHE_TTL,
        "timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
        "max_redirects": DEFAULT_MAX_REDIRECTS,
        "proxy": None,
        "dns": None,
        "allow_insecure": False,
        "log_level": DEFAULT_LOG_LEVEL,
        "log_file": None,
        "config_warnings": [],
        "config_errors": [],
        "_ini_parser": None,
    }


def resolve_scan_config_path(explicit_config: Optional[str], cli_urls: List[str]) -> Optional[str]:
    """Determine which config file (if any) should be loaded for `scan` mode."""

    if(explicit_config is not None):
        return os.path.expanduser(explicit_config)

    # Ad-hoc URL scans skip /etc and ~/.config unless explicitly requested
    if(cli_urls):
        return None

    if(os.path.isfile(USER_CONFIG_PATH) and os.access(USER_CONFIG_PATH, os.R_OK)):
        return USER_CONFIG_PATH

    if(os.path.isfile(SYSTEM_CONFIG_PATH) and os.access(SYSTEM_CONFIG_PATH, os.R_OK)):
        return SYSTEM_CONFIG_PATH

    return None


def build_scan_targets_and_opts(
    explicit_config: Optional[str],
    cli_urls: List[str],
    cli_strategies: List[str],
    profile: Optional[str],
    output_file: Optional[str],
    verify_rdap: Optional[bool],
    no_cache: bool,
    proxy: Optional[str],
    dns_server: Optional[str],
    allow_insecure: bool,
    run_hooks: bool,
) -> Tuple[List[TargetSite], Dict[str, Any]]:
    """Build merged targets and runtime options for interactive `scan` runs."""

    resolved_config = resolve_scan_config_path(explicit_config, cli_urls)

    if(resolved_config is not None):
        targets, global_opts = load_config(resolved_config)
        # Interactive scan runs default to stdout, user RDAP cache, stderr logs, and no post-hooks
        global_opts["output_file"] = STDOUT_TARGET
        global_opts["log_file"] = None
        global_opts["rdap_cache_file"] = USER_CACHE_PATH
        if(not run_hooks):
            global_opts["post_script_dir"] = None
    else:
        targets = []
        global_opts = _build_default_global_opts()

    if(no_cache):
        global_opts["rdap_cache_file"] = None

    if(output_file is not None):
        global_opts["output_file"] = output_file

    if(cli_urls):
        effective_insecure = allow_insecure or global_opts["allow_insecure"]
        ini_parser: Optional[configparser.ConfigParser] = global_opts.get("_ini_parser")
        targets = []

        for raw_url in cli_urls:
            normalised_url, url_warning = validate_and_normalise_url(
                raw_url,
                allow_insecure=effective_insecure,
            )
            site_warnings = [url_warning] if(url_warning) else []
            site_headers = global_opts["default_headers"].copy()

            if(profile and ini_parser is not None):
                site_headers = _extract_profile_headers(ini_parser, site_headers, profile, site_warnings)
            elif(profile):
                site_warnings.append(f"Profile '{profile}' ignored because no config file was loaded.")

            targets.append(
                TargetSite(
                    name="cli",
                    url=normalised_url,
                    strategies=list(global_opts["default_strategies"]),
                    profile=profile,
                    verify_rdap=global_opts["verify_rdap"],
                    ignore_domains=set(global_opts["default_ignore_domains"]),
                    ignore_regexes=list(global_opts["default_ignore_regexes"]),
                    rdap_domain=global_opts["rdap_domain"],
                    headers=site_headers,
                    timeout_seconds=global_opts["timeout_seconds"],
                    max_redirects=global_opts["max_redirects"],
                    proxy=global_opts["proxy"],
                    dns=global_opts["dns"],
                    allow_insecure=effective_insecure,
                    warnings=site_warnings,
                )
            )

    for target in targets:
        if(cli_strategies):
            target.strategies = list(cli_strategies)
        if(verify_rdap is not None):
            target.verify_rdap = verify_rdap
        if(proxy is not None):
            target.proxy = _normalise_optional_str(proxy)
        if(dns_server is not None):
            target.dns = _normalise_optional_str(dns_server)
        if(allow_insecure):
            target.allow_insecure = True

    return targets, global_opts


def validate_config_file(config_path: str) -> Tuple[List[str], List[str]]:
    """Validate an INI configuration file using the production loader."""

    try:
        targets, global_opts = load_config(config_path)
    except (FileNotFoundError, PermissionError, configparser.Error) as exc:
        return [str(exc)], []

    errors: List[str] = list(global_opts.get("config_errors", []))
    warnings: List[str] = list(global_opts.get("config_warnings", []))

    for target in targets:
        for warn in target.warnings:
            warnings.append(f"[{target.name}] {warn}")

    if(not targets):
        errors.append("No target URLs configured under [publishers] or [publisher:<name>].")

    output_file = global_opts.get("output_file")
    if(output_file and output_file != STDOUT_TARGET):
        parent = os.path.dirname(os.path.abspath(output_file))
        if(not os.path.exists(parent)):
            warnings.append(f"Output directory does not exist yet (will be created at runtime): {parent}")
        elif(not os.access(parent, os.W_OK)):
            warnings.append(f"Output directory is not writable by current user: {parent}")

    log_file = global_opts.get("log_file")
    if(log_file):
        log_parent = os.path.dirname(os.path.abspath(log_file))
        if(not os.path.exists(log_parent)):
            warnings.append(f"Log directory does not exist yet (will be created at runtime): {log_parent}")
        elif(not os.access(log_parent, os.W_OK)):
            warnings.append(f"Log directory is not writable by current user: {log_parent}")

    return errors, warnings

# endregion