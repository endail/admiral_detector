import configparser
import hashlib
import os
from typing import Any, Dict, Optional

# region Constants

DEFAULT_PIHOLE_CONFIG_PATH = "/etc/admiral_detector/pihole.conf"
USER_PIHOLE_CONFIG_PATH = os.path.expanduser("~/.config/admiral_detector/pihole.conf")

DEFAULT_MODE = "local"  # 'local' or 'api'
DEFAULT_GRAVITY_DB = "/etc/pihole/gravity.db"
DEFAULT_PIHOLE_BIN = "/usr/local/bin/pihole"
DEFAULT_PIHOLE_FTL_BIN = "/usr/bin/pihole-FTL"

DEFAULT_API_URL = "http://127.0.0.1/api"
DEFAULT_API_TIMEOUT = 15
DEFAULT_VERIFY_SSL = True

DEFAULT_ADLIST_FILE = "/var/lib/admiral_detector/admiral_domains.list"
DEFAULT_PAYLOAD_FILE = "/run/admiral_detector/detected_domains.json"
DEFAULT_LOCK_FILE = "/run/admiral_detector/pihole-sync.lock"
DEFAULT_BATCH_SIZE = 50

DEFAULT_COMMENT_PREFIX = "admiral_detector:staged"
DEFAULT_ADLIST_COMMENT = "Admiral Detector domains"

# endregion


# region Hash Integrity Helpers

def compute_staged_hash(domain: str, salt: str = "admiral_detector") -> str:
    """Compute deterministic short SHA256 integrity hash for a domain."""
    normalized = domain.strip().lower().rstrip(".")
    raw = f"{salt}:{normalized}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


def build_staged_comment(domain: str, prefix: str = DEFAULT_COMMENT_PREFIX) -> str:
    """Construct an integrity-hashed comment string for a staged domain."""
    return f"{prefix}:{compute_staged_hash(domain)}"


def is_staged_comment(comment: Optional[str], domain: str, prefix: str = DEFAULT_COMMENT_PREFIX) -> bool:
    """Verify if a comment belongs to admiral_detector and matches the expected domain hash."""
    if(not comment):
        return False
    comment = comment.strip()
    expected = build_staged_comment(domain, prefix)
    return comment == expected

# endregion


# region Configuration Data Model & Loader

class PiHoleConfig:

    def __init__(
        self,
        config_path: Optional[str] = None,
        mode: str = DEFAULT_MODE,
        gravity_db: str = DEFAULT_GRAVITY_DB,
        pihole_bin: str = DEFAULT_PIHOLE_BIN,
        pihole_ftl_bin: Optional[str] = DEFAULT_PIHOLE_FTL_BIN,
        docker_container: Optional[str] = None,
        api_url: str = DEFAULT_API_URL,
        api_password: Optional[str] = None,
        api_token: Optional[str] = None,
        api_timeout: int = DEFAULT_API_TIMEOUT,
        verify_ssl: bool = DEFAULT_VERIFY_SSL,
        adlist_file: str = DEFAULT_ADLIST_FILE,
        payload_file: str = DEFAULT_PAYLOAD_FILE,
        lock_file: str = DEFAULT_LOCK_FILE,
        batch_size: int = DEFAULT_BATCH_SIZE,
        comment_prefix: str = DEFAULT_COMMENT_PREFIX,
        adlist_comment: str = DEFAULT_ADLIST_COMMENT,
    ):
        self.config_path = config_path
        self.mode = mode.lower().strip()
        self.gravity_db = gravity_db
        self.pihole_bin = pihole_bin
        self.pihole_ftl_bin = pihole_ftl_bin
        self.docker_container = docker_container
        self.api_url = api_url.rstrip("/")
        self.api_password = api_password
        self.api_token = api_token
        self.api_timeout = api_timeout
        self.verify_ssl = verify_ssl
        self.adlist_file = adlist_file
        self.payload_file = payload_file
        self.lock_file = lock_file
        self.batch_size = batch_size
        self.comment_prefix = comment_prefix
        self.adlist_comment = adlist_comment

    @property
    def adlist_uri(self) -> str:
        return f"file://{os.path.abspath(self.adlist_file)}"


def resolve_pihole_config_path(explicit_path: Optional[str] = None) -> Optional[str]:
    """Find the path to pihole.conf if available."""
    if(explicit_path):
        return os.path.abspath(os.path.expanduser(explicit_path))

    for candidate in (USER_PIHOLE_CONFIG_PATH, DEFAULT_PIHOLE_CONFIG_PATH):
        if(os.path.isfile(candidate) and os.access(candidate, os.R_OK)):
            return candidate

    return None


def load_pihole_config(config_path: Optional[str] = None) -> PiHoleConfig:
    """Load configuration from pihole.conf, falling back to defaults and environment."""
    resolved_path = resolve_pihole_config_path(config_path)

    cfg = configparser.ConfigParser(allow_no_value=True, delimiters=("=",))
    cfg.optionxform = str

    if(resolved_path and os.path.isfile(resolved_path)):
        cfg.read(resolved_path, encoding="utf-8")

    # Read section options with fallbacks
    mode = cfg.get("pihole", "mode", fallback=DEFAULT_MODE).strip().lower()

    gravity_db = cfg.get("local", "gravity_db", fallback=DEFAULT_GRAVITY_DB).strip()
    pihole_bin = cfg.get("local", "pihole_bin", fallback=DEFAULT_PIHOLE_BIN).strip()
    raw_ftl = cfg.get("local", "pihole_ftl_bin", fallback=DEFAULT_PIHOLE_FTL_BIN)
    pihole_ftl_bin = raw_ftl.strip() if(raw_ftl and raw_ftl.strip()) else None
    raw_docker = cfg.get("local", "docker_container", fallback=None)
    docker_container = raw_docker.strip() if(raw_docker and raw_docker.strip()) else None

    api_url = cfg.get("api", "url", fallback=DEFAULT_API_URL).strip()
    api_password = cfg.get("api", "password", fallback=None)
    if(api_password):
        api_password = api_password.strip() or None

    api_token = cfg.get("api", "token", fallback=None)
    if(api_token):
        api_token = api_token.strip() or None

    token_env = cfg.get("api", "token_env", fallback=None)
    if(token_env and token_env.strip() in os.environ):
        api_token = os.environ[token_env.strip()]

    api_timeout = cfg.getint("api", "timeout_seconds", fallback=DEFAULT_API_TIMEOUT)
    verify_ssl = cfg.getboolean("api", "verify_ssl", fallback=DEFAULT_VERIFY_SSL)

    adlist_file = cfg.get("sync", "adlist_file", fallback=DEFAULT_ADLIST_FILE).strip()
    payload_file = cfg.get("sync", "payload_file", fallback=DEFAULT_PAYLOAD_FILE).strip()
    lock_file = cfg.get("sync", "lock_file", fallback=DEFAULT_LOCK_FILE).strip()
    batch_size = cfg.getint("sync", "batch_size", fallback=DEFAULT_BATCH_SIZE)
    comment_prefix = cfg.get("sync", "comment_prefix", fallback=DEFAULT_COMMENT_PREFIX).strip()
    adlist_comment = cfg.get("sync", "adlist_comment", fallback=DEFAULT_ADLIST_COMMENT).strip()

    return PiHoleConfig(
        config_path=resolved_path,
        mode=mode,
        gravity_db=gravity_db,
        pihole_bin=pihole_bin,
        pihole_ftl_bin=pihole_ftl_bin,
        docker_container=docker_container,
        api_url=api_url,
        api_password=api_password,
        api_token=api_token,
        api_timeout=api_timeout,
        verify_ssl=verify_ssl,
        adlist_file=adlist_file,
        payload_file=payload_file,
        lock_file=lock_file,
        batch_size=batch_size,
        comment_prefix=comment_prefix,
        adlist_comment=adlist_comment,
    )

# endregion
