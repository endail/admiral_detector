#!/usr/bin/env python3
import argparse
import grp
import importlib.resources
import os
import pwd
import shutil
import sqlite3
import subprocess
import sys
import tempfile

#region Constants
PROJECT_NAME = "admiral_detector"
SERVICE_USER = "admiral"
SERVICE_GROUP = "admiral"
NOLOGIN_SHELL = "/usr/sbin/nologin"

TARGET_BIN = "/usr/local/bin/admiral-detector"
SYNC_HELPER_DEST = "/usr/local/sbin/admiral-pihole-sync"

CONFIG_DIR = "/etc/admiral_detector"
CONFIG_FILE = f"{CONFIG_DIR}/admiral_detector.conf"
POST_SCRIPT_DIR = f"{CONFIG_DIR}/post.d"
POST_SCRIPT_NAME = "99-update-admiral-adlist.sh"
POST_SCRIPT_DEST = f"{POST_SCRIPT_DIR}/{POST_SCRIPT_NAME}"

STATE_DIR = "/var/lib/admiral_detector"
LOG_DIR = "/var/log/admiral_detector"
DEFAULT_OUTPUT_FILE = "/run/admiral_detector/detected_domains.json"

ADLIST_FILE = f"{STATE_DIR}/admiral_domains.list"
ADLIST_URI = f"file://{ADLIST_FILE}"
ADLIST_COMMENT = "Admiral Detector domains"

PIHOLE_BIN = "/usr/local/bin/pihole"
GRAVITY_DB = "/etc/pihole/gravity.db"
SYSTEMD_DIR = "/etc/systemd/system"

DETECTOR_SERVICE_UNIT = "admiral-detector.service"
DETECTOR_TIMER_UNIT = "admiral-detector.timer"
PIHOLE_SYNC_SERVICE_UNIT = "admiral-pihole-sync.service"
PIHOLE_SYNC_PATH_UNIT = "admiral-pihole-sync.path"

DIR_MODE_RESTRICTED = 0o750
DIR_MODE_PUBLIC = 0o755
FILE_MODE_CONFIG = 0o640
FILE_MODE_UNIT = 0o644
FILE_MODE_ADLIST = 0o644
FILE_MODE_HOOK = 0o750
FILE_MODE_EXEC = 0o755

DEFAULT_CONFIG_TEMPLATE = f"""[general]
output_file = {DEFAULT_OUTPUT_FILE}
post_script_dir = {POST_SCRIPT_DIR}/

[rdap]
verify = true
cache_file = {STATE_DIR}/rdap_cache.json

[logging]
level = INFO
file = {LOG_DIR}/admiral_detector.log

[publishers]
techcrunch.com
"""
#endregion


#region Helpers
def require_root() -> None:
    if(os.geteuid() != 0):
        print("Error: This setup command must be run as root (use sudo).", file=sys.stderr)
        sys.exit(1)


def read_packaged_asset(relative_path: str) -> bytes:
    asset = importlib.resources.files(PROJECT_NAME).joinpath(relative_path)
    return asset.read_bytes()


def write_file_atomic(dest_path: str, content: bytes, uid: int, gid: int, mode: int) -> None:

    parent_dir = os.path.dirname(dest_path)
    os.makedirs(parent_dir, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_admiral_", dir=parent_dir)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        os.chown(tmp_path, uid, gid)
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, dest_path)
    except Exception:
        if(os.path.exists(tmp_path)):
            os.unlink(tmp_path)
        raise


def ensure_directory(path: str, uid: int, gid: int, mode: int) -> None:
    os.makedirs(path, exist_ok=True)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def pihole_detected() -> bool:
    return os.path.isfile(PIHOLE_BIN) and os.access(PIHOLE_BIN, os.X_OK) and os.path.isfile(GRAVITY_DB)


def prompt_yes_no(prompt_text: str, default_answer: bool) -> bool:

    suffix = "[Y/n]" if default_answer else "[y/N]"
    while(True):
        reply = input(f"{prompt_text} {suffix}: ").strip().lower()
        if(not reply):
            return default_answer
        if(reply in ("y", "yes")):
            return True
        if(reply in ("n", "no")):
            return False
        print("Please answer 'y' or 'n'.")


def resolve_detector_binary(explicit_path: str | None) -> str:

    if(explicit_path):
        resolved = os.path.abspath(explicit_path)
        if(not os.path.isfile(resolved) or not os.access(resolved, os.X_OK)):
            raise FileNotFoundError(f"Specified binary is not executable: {resolved}")
        return resolved

    sibling_bin = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "admiral-detector")
    if(os.path.isfile(sibling_bin) and os.access(sibling_bin, os.X_OK)):
        return sibling_bin

    which_bin = shutil.which("admiral-detector")
    if(which_bin):
        return os.path.abspath(which_bin)

    raise FileNotFoundError(
        "Could not locate 'admiral-detector' executable. Pass --bin-path <path> explicitly."
    )
#endregion


#region Core Detector Setup
def ensure_service_account() -> tuple[int, int]:

    try:
        gid = grp.getgrnam(SERVICE_GROUP).gr_gid
    except KeyError:
        subprocess.run(["groupadd", "--system", SERVICE_GROUP], check=True)
        gid = grp.getgrnam(SERVICE_GROUP).gr_gid
        print(f"Created system group: {SERVICE_GROUP}")

    try:
        uid = pwd.getpwnam(SERVICE_USER).pw_uid
        print(f"System user '{SERVICE_USER}' already exists.")
    except KeyError:
        subprocess.run(
            [
                "useradd",
                "--system",
                "--gid",
                SERVICE_GROUP,
                "--no-create-home",
                "--shell",
                NOLOGIN_SHELL,
                SERVICE_USER,
            ],
            check=True,
        )
        uid = pwd.getpwnam(SERVICE_USER).pw_uid
        print(f"Created system user: {SERVICE_USER}")

    return uid, gid


def link_detector_binary(source_bin: str) -> None:

    if(os.path.abspath(source_bin) == os.path.abspath(TARGET_BIN)):
        print(f"Binary already installed at {TARGET_BIN}")
        return

    os.makedirs(os.path.dirname(TARGET_BIN), exist_ok=True)
    tmp_link = f"{TARGET_BIN}.tmp.{os.getpid()}"
    os.symlink(source_bin, tmp_link)
    os.replace(tmp_link, TARGET_BIN)
    print(f"Linked {TARGET_BIN} -> {source_bin}")


def setup_core_detector(source_bin: str) -> None:

    print("--- Configuring Core Detector Service ---")
    link_detector_binary(source_bin)
    uid, gid = ensure_service_account()

    ensure_directory(CONFIG_DIR, 0, gid, DIR_MODE_RESTRICTED)
    ensure_directory(POST_SCRIPT_DIR, 0, gid, DIR_MODE_RESTRICTED)
    ensure_directory(STATE_DIR, uid, gid, DIR_MODE_PUBLIC)
    ensure_directory(LOG_DIR, uid, gid, DIR_MODE_RESTRICTED)
    print(f"Configured directories under {CONFIG_DIR}, {STATE_DIR}, and {LOG_DIR}.")

    if(not os.path.exists(CONFIG_FILE)):
        write_file_atomic(
            CONFIG_FILE,
            DEFAULT_CONFIG_TEMPLATE.encode("utf-8"),
            0,
            gid,
            FILE_MODE_CONFIG,
        )
        print(f"Created default configuration: {CONFIG_FILE}")
    else:
        print(f"Existing configuration preserved: {CONFIG_FILE}")

    for unit_name in (DETECTOR_SERVICE_UNIT, DETECTOR_TIMER_UNIT):
        unit_bytes = read_packaged_asset(f"data/systemd/{unit_name}")
        dest_path = f"{SYSTEMD_DIR}/{unit_name}"
        write_file_atomic(dest_path, unit_bytes, 0, 0, FILE_MODE_UNIT)
        print(f"Installed {dest_path}")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", DETECTOR_TIMER_UNIT], check=True)
    print(f"Enabled and started {DETECTOR_TIMER_UNIT}.")
#endregion


#region Pi-hole Sync Setup
def setup_pihole_sync() -> None:

    print("\n--- Configuring Pi-hole Sync Integration ---")
    if(not os.path.isfile(PIHOLE_BIN) or not os.access(PIHOLE_BIN, os.X_OK)):
        raise FileNotFoundError(f"Pi-hole CLI not found at {PIHOLE_BIN}.")

    if(not os.path.isfile(GRAVITY_DB)):
        raise FileNotFoundError(f"Pi-hole gravity database not found at {GRAVITY_DB}.")

    uid, gid = ensure_service_account()
    ensure_directory(CONFIG_DIR, 0, gid, DIR_MODE_RESTRICTED)
    ensure_directory(POST_SCRIPT_DIR, 0, gid, DIR_MODE_RESTRICTED)
    ensure_directory(STATE_DIR, uid, gid, DIR_MODE_PUBLIC)

    if(not os.path.exists(ADLIST_FILE)):
        write_file_atomic(ADLIST_FILE, b"", uid, gid, FILE_MODE_ADLIST)
        print(f"Created empty domain list: {ADLIST_FILE}")
    else:
        os.chown(ADLIST_FILE, uid, gid)
        os.chmod(ADLIST_FILE, FILE_MODE_ADLIST)

    hook_bytes = read_packaged_asset(f"data/integrations/pihole/{POST_SCRIPT_NAME}")
    write_file_atomic(POST_SCRIPT_DEST, hook_bytes, 0, gid, FILE_MODE_HOOK)
    print(f"Installed {POST_SCRIPT_DEST}")

    helper_bytes = read_packaged_asset("data/integrations/pihole/admiral-pihole-sync")
    write_file_atomic(SYNC_HELPER_DEST, helper_bytes, 0, 0, FILE_MODE_EXEC)
    print(f"Installed {SYNC_HELPER_DEST}")

    with sqlite3.connect(GRAVITY_DB) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO adlist (address, enabled, comment) VALUES (?, 1, ?)",
            (ADLIST_URI, ADLIST_COMMENT),
        )
        conn.commit()
    print(f"Registered adlist in Pi-hole: {ADLIST_URI}")

    for unit_name in (PIHOLE_SYNC_SERVICE_UNIT, PIHOLE_SYNC_PATH_UNIT):
        unit_bytes = read_packaged_asset(f"data/integrations/pihole/{unit_name}")
        dest_path = f"{SYSTEMD_DIR}/{unit_name}"
        write_file_atomic(dest_path, unit_bytes, 0, 0, FILE_MODE_UNIT)
        print(f"Installed {dest_path}")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", PIHOLE_SYNC_PATH_UNIT], check=True)
    print(f"Enabled and started {PIHOLE_SYNC_PATH_UNIT}.")
#endregion


#region Entry Point
def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        prog="admiral-detector-setup",
        description="Provision systemd services and optional Pi-hole sync for admiral_detector.",
    )
    parser.add_argument(
        "-y",
        "--non-interactive",
        action="store_true",
        help="Run without interactive prompts using defaults or explicit flags.",
    )
    parser.add_argument(
        "--bin-path",
        default=None,
        help="Path to the admiral-detector executable to symlink to /usr/local/bin/admiral-detector.",
    )

    pihole_group = parser.add_mutually_exclusive_group()
    pihole_group.add_argument(
        "--with-pihole-sync",
        action="store_true",
        help="Configure the Pi-hole adlist and denylist sync integration.",
    )
    pihole_group.add_argument(
        "--without-pihole-sync",
        action="store_true",
        help="Skip configuring the Pi-hole sync integration.",
    )
    pihole_group.add_argument(
        "--pihole-sync-only",
        action="store_true",
        help="Only configure the Pi-hole sync integration (assumes core detector is already set up).",
    )

    parser.add_argument(
        "--run-now",
        action="store_true",
        help="Trigger an immediate test scan after setup completes.",
    )
    return parser.parse_args()


def main() -> None:

    args = parse_args()
    require_root()

    interactive = (not args.non_interactive) and sys.stdin.isatty()
    configure_pihole = args.with_pihole_sync or args.pihole_sync_only
    run_now = args.run_now

    if(not args.pihole_sync_only and not args.with_pihole_sync and not args.without_pihole_sync):
        if(interactive):
            configure_pihole = prompt_yes_no(
                "Configure Pi-hole domain sync integration?",
                pihole_detected(),
            )

    if(interactive and not run_now):
        run_now = prompt_yes_no("Trigger an immediate test scan once setup completes?", False)

    if(not args.pihole_sync_only):
        source_bin = resolve_detector_binary(args.bin_path)
        setup_core_detector(source_bin)

    if(configure_pihole):
        setup_pihole_sync()
    elif(not args.pihole_sync_only):
        print("\nSkipping Pi-hole sync integration (run 'sudo admiral-detector-setup --pihole-sync-only' later to enable).")

    if(run_now):
        print("\n--- Running Initial Detection Scan ---")
        subprocess.run(["systemctl", "start", DETECTOR_SERVICE_UNIT], check=True)
        subprocess.run(["journalctl", "-u", DETECTOR_SERVICE_UNIT, "-n", "25", "--no-pager"], check=True)

    print("\nSetup complete.")


if(__name__ == "__main__"):
    main()