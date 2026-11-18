#!/usr/bin/env bash
set -euo pipefail;

#region Constants
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)";
readonly SERVICE_USER="admiral";
readonly SERVICE_GROUP="admiral";

readonly POST_SCRIPT_NAME="99-update-admiral-adlist.sh";
readonly POST_SCRIPT_DEST="/etc/admiral_detector/post.d/${POST_SCRIPT_NAME}";

readonly SYNC_HELPER_NAME="admiral-pihole-sync";
readonly SYNC_HELPER_DEST="/usr/local/sbin/${SYNC_HELPER_NAME}";

readonly STATE_DIR="/var/lib/admiral_detector";
readonly ADLIST_FILE="${STATE_DIR}/admiral_domains.list";
readonly ADLIST_URI="file://${ADLIST_FILE}";
readonly ADLIST_COMMENT="Admiral Detector domains";

readonly PIHOLE_BIN="/usr/local/bin/pihole";
readonly GRAVITY_DB="/etc/pihole/gravity.db";
readonly SYSTEMD_DIR="/etc/systemd/system";

readonly UNIT_FILES=(
    "admiral-pihole-sync.service"
    "admiral-pihole-sync.path"
);
#endregion

#region Functions
require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "Error: This script must be run as root (use sudo)." >&2;
        exit 1;
    fi;
}

check_prerequisites() {

    if [[ ! -x "${PIHOLE_BIN}" ]]; then
        echo "Error: Pi-hole CLI not found at ${PIHOLE_BIN}." >&2;
        exit 1;
    fi;

    if [[ ! -f "${GRAVITY_DB}" ]]; then
        echo "Error: Pi-hole gravity database not found at ${GRAVITY_DB}." >&2;
        exit 1;
    fi;

    if [[ ! -f "${SCRIPT_DIR}/${POST_SCRIPT_NAME}" ]]; then
        echo "Error: Missing ${POST_SCRIPT_NAME} in ${SCRIPT_DIR}." >&2;
        exit 1;
    fi;

    if [[ ! -f "${SCRIPT_DIR}/${SYNC_HELPER_NAME}" ]]; then
        echo "Error: Missing ${SYNC_HELPER_NAME} in ${SCRIPT_DIR}." >&2;
        exit 1;
    fi;

    local unit_file;
    for unit_file in "${UNIT_FILES[@]}"; do
        if [[ ! -f "${SCRIPT_DIR}/${unit_file}" ]]; then
            echo "Error: Missing ${unit_file} in ${SCRIPT_DIR}." >&2;
            exit 1;
        fi;
    done;

}

install_files() {

    install -d -o root -g "${SERVICE_GROUP}" -m 0750 "/etc/admiral_detector" "/etc/admiral_detector/post.d";
    install -d -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0755 "${STATE_DIR}";

    if [[ ! -f "${ADLIST_FILE}" ]]; then
        install -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" -m 0644 /dev/null "${ADLIST_FILE}";
        echo "Created empty domain list: ${ADLIST_FILE}";
    else
        chown "${SERVICE_USER}":"${SERVICE_GROUP}" "${ADLIST_FILE}";
        chmod 0644 "${ADLIST_FILE}";
    fi;

    install -o root -g "${SERVICE_GROUP}" -m 0750 "${SCRIPT_DIR}/${POST_SCRIPT_NAME}" "${POST_SCRIPT_DEST}";
    echo "Installed ${POST_SCRIPT_DEST}";

    install -o root -g root -m 0755 "${SCRIPT_DIR}/${SYNC_HELPER_NAME}" "${SYNC_HELPER_DEST}";
    echo "Installed ${SYNC_HELPER_DEST}";

}

register_pihole_adlist() {

    python3 - "${GRAVITY_DB}" "${ADLIST_URI}" "${ADLIST_COMMENT}" << 'PYEOF'
#!/usr/bin/env python3
import sqlite3
import sys

db_path = sys.argv[1]
adlist_uri = sys.argv[2]
comment = sys.argv[3]

with sqlite3.connect(db_path) as conn:
    conn.execute(
        "INSERT OR IGNORE INTO adlist (address, enabled, comment) VALUES (?, 1, ?)",
        (adlist_uri, comment),
    )
    conn.commit()
PYEOF

    echo "Registered adlist in Pi-hole: ${ADLIST_URI}";

}

install_systemd_units() {

    local unit_file;
    for unit_file in "${UNIT_FILES[@]}"; do
        install -o root -g root -m 0644 "${SCRIPT_DIR}/${unit_file}" "${SYSTEMD_DIR}/${unit_file}";
        echo "Installed ${SYSTEMD_DIR}/${unit_file}";
    done;

    systemctl daemon-reload;
    systemctl enable --now admiral-pihole-sync.path;
    echo "Enabled and started admiral-pihole-sync.path.";

}

main() {

    require_root;
    check_prerequisites;
    install_files;
    register_pihole_adlist;
    install_systemd_units;

    echo "";
    echo "Pi-hole sync setup complete.";
    echo "Verify end-to-end with: sudo systemctl start admiral-detector.service && journalctl -u admiral-detector.service -u admiral-pihole-sync.service -n 40";

}
#endregion

main "$@";