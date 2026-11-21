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
RUNTIME_DIR = "/run/admiral_detector"
DEFAULT_OUTPUT_FILE = f"{RUNTIME_DIR}/detected_domains.json"

ADLIST_FILE = f"{STATE_DIR}/admiral_domains.list"
ADLIST_URI = f"file://{ADLIST_FILE}"
ADLIST_COMMENT = "Admiral Detector domains"
STAGED_COMMENT = "Admiral Detector staged"
WILDCARD_DOMAIN_TYPE = 3

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

[daemon]
interval = 1h
random_delay = 5m
initial_delay = 0s

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


def remove_file_if_exists(path: str) -> bool:

    if(os.path.lexists(path)):
        os.unlink(path)
        return True

    return False


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

    # Remove legacy timer if previously installed
    subprocess.run(["systemctl", "disable", "--now", DETECTOR_TIMER_UNIT], check=False, stderr=subprocess.DEVNULL)
    if(remove_file_if_exists(f"{SYSTEMD_DIR}/{DETECTOR_TIMER_UNIT}")):
        print(f"Removed legacy {DETECTOR_TIMER_UNIT}")

    unit_bytes = read_packaged_asset(f"data/systemd/{DETECTOR_SERVICE_UNIT}")
    dest_path = f"{SYSTEMD_DIR}/{DETECTOR_SERVICE_UNIT}"
    write_file_atomic(dest_path, unit_bytes, 0, 0, FILE_MODE_UNIT)
    print(f"Installed {dest_path}")

    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", DETECTOR_SERVICE_UNIT], check=True)
    print(f"Enabled and started {DETECTOR_SERVICE_UNIT}.")
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


#region Uninstall & Purge
def uninstall_pihole_sync() -> None:

    print("--- Removing Pi-hole Sync Integration ---")
    subprocess.run(["systemctl", "disable", "--now", PIHOLE_SYNC_PATH_UNIT], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "stop", PIHOLE_SYNC_SERVICE_UNIT], check=False, stderr=subprocess.DEVNULL)

    for unit_name in (PIHOLE_SYNC_PATH_UNIT, PIHOLE_SYNC_SERVICE_UNIT):
        dest_path = f"{SYSTEMD_DIR}/{unit_name}"
        if(remove_file_if_exists(dest_path)):
            print(f"Removed {dest_path}")

    if(remove_file_if_exists(POST_SCRIPT_DEST)):
        print(f"Removed {POST_SCRIPT_DEST}")

    if(remove_file_if_exists(SYNC_HELPER_DEST)):
        print(f"Removed {SYNC_HELPER_DEST}")

    if(os.path.isfile(GRAVITY_DB)):
        db_changed = False
        with sqlite3.connect(GRAVITY_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM adlist WHERE address = ?", (ADLIST_URI,))
            adlist_row = cursor.fetchone()
            if(adlist_row is not None):
                adlist_id = int(adlist_row[0])
                cursor.execute("DELETE FROM gravity WHERE adlist_id = ?", (adlist_id,))
                cursor.execute("DELETE FROM adlist WHERE id = ?", (adlist_id,))
                db_changed = True

            cursor.execute(
                "DELETE FROM domainlist WHERE type = ? AND comment = ?",
                (WILDCARD_DOMAIN_TYPE, STAGED_COMMENT),
            )
            if(cursor.rowcount > 0):
                db_changed = True

            conn.commit()

        if(db_changed):
            print("Removed Admiral adlist and staged denylist entries from Pi-hole.")
            if(os.path.isfile(PIHOLE_BIN) and os.access(PIHOLE_BIN, os.X_OK)):
                subprocess.run([PIHOLE_BIN, "reloadlists"], check=False)


def uninstall_core_detector(purge: bool) -> None:

    print("\n--- Removing Core Detector Service ---")
    subprocess.run(["systemctl", "disable", "--now", DETECTOR_SERVICE_UNIT], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "stop", DETECTOR_SERVICE_UNIT], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "disable", "--now", DETECTOR_TIMER_UNIT], check=False, stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "stop", DETECTOR_TIMER_UNIT], check=False, stderr=subprocess.DEVNULL)

    for unit_name in (DETECTOR_SERVICE_UNIT, DETECTOR_TIMER_UNIT):
        dest_path = f"{SYSTEMD_DIR}/{unit_name}"
        if(remove_file_if_exists(dest_path)):
            print(f"Removed {dest_path}")

    subprocess.run(["systemctl", "daemon-reload"], check=False)
    subprocess.run(["systemctl", "reset-failed"], check=False, stderr=subprocess.DEVNULL)

    if(os.path.islink(TARGET_BIN)):
        os.unlink(TARGET_BIN)
        print(f"Removed symlink {TARGET_BIN}")

    if(os.path.exists(RUNTIME_DIR)):
        shutil.rmtree(RUNTIME_DIR, ignore_errors=True)

    if(purge):
        print("\n--- Purging Configuration, State, Logs, and Service Account ---")
        for directory in (CONFIG_DIR, STATE_DIR, LOG_DIR):
            if(os.path.exists(directory)):
                shutil.rmtree(directory)
                print(f"Removed directory {directory}")

        try:
            pwd.getpwnam(SERVICE_USER)
            subprocess.run(["userdel", SERVICE_USER], check=True)
            print(f"Removed system user: {SERVICE_USER}")
        except KeyError:
            pass

        try:
            grp.getgrnam(SERVICE_GROUP)
            subprocess.run(["groupdel", SERVICE_GROUP], check=True)
            print(f"Removed system group: {SERVICE_GROUP}")
        except KeyError:
            pass
    else:
        print(
            f"\nPreserved configuration, domain lists, and logs in {CONFIG_DIR}, {STATE_DIR}, and {LOG_DIR}."
        )
        print("Re-run with '--purge' to delete those directories and the 'admiral' system user.")
#endregion


#region Entry Point
def parse_args() -> argparse.Namespace:

    parser = argparse.ArgumentParser(
        prog="admiral-detector-setup",
        description="Provision or remove systemd services and optional Pi-hole sync for admiral_detector.",
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

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--with-pihole-sync",
        action="store_true",
        help="Configure the Pi-hole adlist and denylist sync integration.",
    )
    mode_group.add_argument(
        "--without-pihole-sync",
        action="store_true",
        help="Skip configuring the Pi-hole sync integration.",
    )
    mode_group.add_argument(
        "--pihole-sync-only",
        action="store_true",
        help="Only configure the Pi-hole sync integration (assumes core detector is already set up).",
    )
    mode_group.add_argument(
        "--uninstall",
        action="store_true",
        help="Remove systemd units, binary symlink, and Pi-hole integration while keeping config and data.",
    )
    mode_group.add_argument(
        "--purge",
        action="store_true",
        help="Completely remove services, Pi-hole integration, config, state, logs, and the admiral user.",
    )
    mode_group.add_argument(
        "--uninstall-pihole-sync",
        action="store_true",
        help="Remove only the Pi-hole sync integration while keeping the core detector running.",
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

    if(args.uninstall_pihole_sync):
        uninstall_pihole_sync()
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        print("\nPi-hole sync integration removed.")
        return

    if(args.uninstall or args.purge):
        purge = args.purge
        if(interactive and not purge):
            purge = prompt_yes_no(
                f"Also delete configuration, domain lists, logs ({CONFIG_DIR}, {STATE_DIR}, {LOG_DIR}), and the '{SERVICE_USER}' user?",
                False,
            )
        uninstall_pihole_sync()
        uninstall_core_detector(purge)
        print("\nUninstall complete. To remove the Python package itself, delete its virtual environment (e.g. 'rm -rf .venv') or run 'pipx uninstall admiral-detector'.")
        return

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
        print("\n--- Triggering Initial Detection Scan ---")
        subprocess.run(["systemctl", "restart", DETECTOR_SERVICE_UNIT], check=True)
        subprocess.run(["journalctl", "-u", DETECTOR_SERVICE_UNIT, "-n", "25", "--no-pager"], check=True)

    print("\nSetup complete.")


if(__name__ == "__main__"):
    main()