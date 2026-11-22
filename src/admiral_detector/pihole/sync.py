import argparse
import contextlib
import logging
import os
import sys
from typing import Iterator, List, Optional, Tuple

from .adlist import load_existing_adlist_domains
from .backends import get_backend
from .config import PiHoleConfig, load_pihole_config

logger = logging.getLogger("AdmiralDetector.PiHole.Sync")


@contextlib.contextmanager
def acquire_sync_lock(lock_path: str) -> Iterator[None]:
    """Acquire a non-blocking flock to prevent concurrent sync executions."""
    parent = os.path.dirname(os.path.abspath(lock_path))
    os.makedirs(parent, exist_ok=True)

    with open(lock_path, "a+") as handle:
        has_flock = False
        try:
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            has_flock = True
        except (ImportError, AttributeError):
            # Non-Unix environments (Windows fallback)
            pass
        except (BlockingIOError, OSError) as exc:
            raise RuntimeError(f"Another sync process is already running (lock held on {lock_path}).") from exc

        try:
            yield
        finally:
            if(has_flock):
                try:
                    import fcntl
                    fcntl.flock(handle, fcntl.LOCK_UN)
                except Exception:
                    pass


def run_pihole_sync(config: PiHoleConfig, dry_run: bool = False) -> bool:
    """Execute complete synchronization between adlist file and Pi-hole."""
    if(not os.path.isfile(config.adlist_file)):
        raise FileNotFoundError(f"Adlist file missing: {config.adlist_file}")

    backend = get_backend(config)
    backend.check_prerequisites()
    backend.check_adlist_syntax(config.adlist_file)

    # 1. Ensure the adlist is registered in Pi-hole
    if(not dry_run):
        backend.ensure_adlist(config.adlist_uri, config.adlist_comment)

    # 2. Load candidate domains from local adlist
    list_domains = load_existing_adlist_domains(config.adlist_file)
    logger.info(f"Loaded {len(list_domains)} domain(s) from local adlist ({config.adlist_file}).")

    # 3. Query compiled domains in gravity
    compiled_domains = backend.get_compiled_domains(config.adlist_uri)
    logger.info(f"Found {len(compiled_domains)} domain(s) already compiled into Pi-hole gravity.")

    # 4. Query active staged domains with integrity verification
    staged_domains = backend.get_staged_domains()
    logger.info(f"Found {len(staged_domains)} active staged wildcard domain(s) in Pi-hole denylist.")

    # 5. Identify stale / now-compiled entries to unstage
    stale_entries: List[Tuple[str, dict]] = []
    active_staged: set = set()

    for domain, details in staged_domains.items():
        if(domain in compiled_domains or domain not in list_domains):
            stale_entries.append((domain, details))
        else:
            active_staged.add(domain)

    # 6. Identify new domains needing immediate staging
    domains_to_stage = sorted(list_domains - compiled_domains - active_staged)

    changed = False

    if(stale_entries):
        logger.info(f"Cleaning up {len(stale_entries)} compiled or removed staged domain(s)...")
        if(not dry_run):
            backend.unstage_domains(stale_entries)
        changed = True

    if(domains_to_stage):
        logger.info(f"Staging {len(domains_to_stage)} new uncompiled domain(s) into wildcard denylist...")
        if(not dry_run):
            backend.stage_domains(domains_to_stage)
        changed = True

    if(changed and not dry_run):
        backend.reload_lists()
        logger.info("Pi-hole lists successfully synchronized and reloaded.")
    elif(not changed):
        logger.info("Pi-hole denylist already in sync; no changes required.")

    return changed


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admiral-pihole-sync",
        description="Synchronise Admiral Detector domains with Pi-hole (staged denylist + adlist).",
    )
    parser.add_argument("-c", "--config", help="Path to pihole.conf.")
    parser.add_argument("--dry-run", action="store_true", help="Report planned changes without modifying Pi-hole.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging.")

    args = parser.parse_args(argv)

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s - %(levelname)s - %(message)s")

    cfg = load_pihole_config(args.config)

    try:
        with acquire_sync_lock(cfg.lock_file):
            run_pihole_sync(cfg, dry_run=args.dry_run)
        return 0
    except RuntimeError as rerr:
        logger.warning(str(rerr))
        return 0
    except Exception as exc:
        logger.error(f"Pi-hole sync failed: {exc}", exc_info=args.verbose)
        return 1


if(__name__ == "__main__"):
    sys.exit(main())
