#!/usr/bin/env bash
set -euo pipefail;

#region Constants
readonly DEFAULT_PAYLOAD_PATH="/run/admiral_detector/detected_domains.json";
readonly ADLIST_PATH="/var/lib/admiral_detector/admiral_domains.list";
readonly PAYLOAD_PATH="${1:-${DEFAULT_PAYLOAD_PATH}}";
#endregion

main() {

    if [[ ! -f "${PAYLOAD_PATH}" ]]; then
        echo "Payload file not found: ${PAYLOAD_PATH}" >&2;
        exit 1;
    fi;

    python3 - "${PAYLOAD_PATH}" "${ADLIST_PATH}" << 'PYEOF'
#!/usr/bin/env python3
import json
import os
import re
import sys
import tempfile

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
FILE_MODE = 0o644


def load_detected_domains(payload_path: str) -> set[str]:

    with open(payload_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if(not isinstance(payload, dict)):
        raise ValueError("Invalid JSON root structure: expected object.")

    metadata = payload.get("metadata")
    if(not isinstance(metadata, dict)):
        raise ValueError("Invalid JSON payload: missing 'metadata' object.")

    raw_domains = metadata.get("unique_domains")
    if(not isinstance(raw_domains, list)):
        raise ValueError("Invalid JSON payload: 'metadata.unique_domains' must be a list.")

    valid_domains: set[str] = set()
    for entry in raw_domains:
        if(not isinstance(entry, str)):
            continue
        cleaned = entry.strip().lower().rstrip(".")
        if(DOMAIN_REGEX.match(cleaned)):
            valid_domains.add(cleaned)
        elif(cleaned):
            print(f"Skipping invalid domain entry: {cleaned}", file=sys.stderr)

    return valid_domains


def load_existing_domains(adlist_path: str) -> set[str]:

    if(not os.path.exists(adlist_path)):
        return set()

    existing: set[str] = set()
    with open(adlist_path, "r", encoding="utf-8") as handle:
        for line in handle:
            cleaned = line.strip().lower().rstrip(".")
            if(cleaned and not cleaned.startswith("#") and DOMAIN_REGEX.match(cleaned)):
                existing.add(cleaned)

    return existing


def write_adlist_atomically(adlist_path: str, domains: list[str]) -> None:

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


def main() -> None:

    payload_path = sys.argv[1]
    adlist_path = sys.argv[2]

    detected = load_detected_domains(payload_path)
    if(not detected):
        print("No valid domains detected in payload; adlist unchanged.")
        return

    existing = load_existing_domains(adlist_path)
    merged = sorted(existing.union(detected))

    if(len(merged) == len(existing)):
        print("No new Admiral domains to add; adlist unchanged.")
        return

    added_count = len(merged) - len(existing)
    write_adlist_atomically(adlist_path, merged)
    print(f"Added {added_count} new domain(s) to {adlist_path} (total: {len(merged)}).")


if(__name__ == "__main__"):
    main()
PYEOF

}

main "$@";