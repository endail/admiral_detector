#!/usr/bin/env bash
set -euo pipefail;

readonly PAYLOAD_PATH="${1:-/run/admiral_detector/detected_domains.json}";

if [[ ! -f "${PAYLOAD_PATH}" ]]; then
    echo "Payload file not found: ${PAYLOAD_PATH}" >&2;
    exit 1;
fi;

exec /usr/local/bin/admiral-detector update-pihole-adlist "${PAYLOAD_PATH}";
