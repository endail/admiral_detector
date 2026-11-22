import argparse
import json
import logging
import os
import re
import sys
import tempfile
from typing import List, Optional, Set, Tuple

from .config import DEFAULT_ADLIST_FILE, load_pihole_config

logger = logging.getLogger("AdmiralDetector.PiHole.Adlist")

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
FILE_MODE = 0o644


def load_detected_domains(payload_path: str) -> Set[str]:
    """Extract and validate unique domains from detector JSON output."""
    if(not os.path.isfile(payload_path)):
        raise FileNotFoundError(f"Detector payload file missing: {payload_path}")

    with open(payload_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if(not isinstance(payload, dict)):
        raise ValueError("Invalid JSON root structure: expected dictionary object.")

    metadata = payload.get("metadata")
    if(not isinstance(metadata, dict)):
        raise ValueError("Invalid JSON payload: missing 'metadata' dictionary.")

    raw_domains = metadata.get("unique_domains")
    if(not isinstance(raw_domains, list)):
        raise ValueError("Invalid JSON payload: 'metadata.unique_domains' must be a list.")

    valid_domains: Set[str] = set()
    for entry in raw_domains:
        if(not isinstance(entry, str)):
            continue
        cleaned = entry.strip().lower().rstrip(".")
        if(DOMAIN_REGEX.match(cleaned)):
            valid_domains.add(cleaned)
        elif(cleaned):
            logger.warning(f"Skipping invalid domain entry in payload: {cleaned}")

    return valid_domains


def load_existing_adlist_domains(adlist_path: str) -> Set[str]:
    """Read existing domains from the adlist file."""
    if(not os.path.exists(adlist_path)):
        return set()

    existing: Set[str] = set()
    with open(adlist_path, "r", encoding="utf-8") as handle:
        for line in handle:
            cleaned = line.strip().lower().rstrip(".")
            if(cleaned and not cleaned.startswith("#") and DOMAIN_REGEX.match(cleaned)):
                existing.add(cleaned)

    return existing


def write_adlist_atomically(adlist_path: str, domains: List[str]) -> None:
    """Write sorted domain list atomically using a tempfile and os.replace."""
    parent_dir = os.path.dirname(os.path.abspath(adlist_path))
    os.makedirs(parent_dir, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".admiral_domains.", dir=parent_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            for domain in domains:
                handle.write(f"{domain}\n")
        os.chmod(tmp_path, FILE_MODE)
        os.replace(tmp_path, adlist_path)
    except Exception:
        if(os.path.exists(tmp_path)):
            os.unlink(tmp_path)
        raise


def update_adlist_from_payload(payload_path: str, adlist_path: str) -> Tuple[int, int]:
    """Extract domains from payload, merge with existing adlist, and atomically update.
    Returns (added_count, total_count).
    """
    detected = load_detected_domains(payload_path)
    if(not detected):
        logger.info("No valid domains found in payload; adlist left unchanged.")
        existing = load_existing_adlist_domains(adlist_path)
        return (0, len(existing))

    existing = load_existing_adlist_domains(adlist_path)
    merged = sorted(existing.union(detected))
    added_count = len(merged) - len(existing)

    if(added_count == 0):
        logger.info(f"No new Admiral domains to add (total: {len(merged)}); adlist unchanged.")
        return (0, len(merged))

    write_adlist_atomically(adlist_path, merged)
    logger.info(f"Added {added_count} new domain(s) to {adlist_path} (total: {len(merged)}).")
    return (added_count, len(merged))


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="admiral-detector update-pihole-adlist",
        description="Ingest detector JSON payload and update Pi-hole adlist file.",
    )
    parser.add_argument("payload", nargs="?", help="Path to detected_domains.json output.")
    parser.add_argument("-c", "--config", help="Path to pihole.conf.")
    parser.add_argument("-o", "--adlist", help="Override adlist output file path.")

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

    cfg = load_pihole_config(args.config)
    payload_path = args.payload or cfg.payload_file
    adlist_path = args.adlist or cfg.adlist_file

    try:
        added, total = update_adlist_from_payload(payload_path, adlist_path)
        print(f"Adlist updated: +{added} new, {total} total domains.")
        return 0
    except Exception as exc:
        logger.error(f"Failed to update adlist: {exc}")
        return 1


if(__name__ == "__main__"):
    sys.exit(main())
