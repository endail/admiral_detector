# admiral_detector

`admiral_detector` is a Python tool and `systemd` service that scans configured publisher websites to detect dynamically rotated Admiral (Leven Labs) anti-adblock domains, verifies domain registrations via RDAP, and outputs structured JSON metadata with optional post-run hooks and Pi-hole integration.

## Features

* **Modular Detection Strategies:** Extracts candidate anti-adblock domains from inline scripts, obfuscated payloads, and script heuristics.
* **RDAP Verification & Caching:** Validates candidate domains against RDAP endpoints (such as `rdap.org` and registrar servers) with local JSON caching to avoid redundant lookups.
* **Privilege-Separated `systemd` Service:** Runs scheduled scans under a dedicated, unprivileged `admiral` system account with hardened `systemd` unit restrictions.
* **Zero-Rebuild Pi-hole Integration:** Stages newly discovered domains immediately into Pi-hole's wildcard denylist (`pihole reloadlists`) without triggering slow `pihole -g` gravity rebuilds, then automatically cleans up staged entries once weekly gravity runs ingest the local adlist.
* **Packaged Setup CLI:** Includes `admiral-detector-setup` to provision, update, or cleanly remove `systemd` units and Pi-hole integration interactively or non-interactively.

## Requirements

* **Python:** 3.11 or newer
* **Python Dependencies** (installed automatically via `pyproject.toml`):
  * `beautifulsoup4 >= 4.12.0`
  * `httpx >= 0.25.0`
  * `tldextract >= 3.4.0`
  * `dnspython >= 2.3.0`
* **Optional System Integrations:**
  * Linux with `systemd` (for scheduled background execution)
  * Pi-hole with `/usr/local/bin/pihole` and `/etc/pihole/gravity.db` (for automatic DNS blocking)

## Project Structure

```text
admiral_detector/
├── Makefile
├── pyproject.toml
├── README.md
├── LICENSE
├── admiral_detector.conf.barebones.example
├── admiral_detector.conf.full.example
└── src/
    └── admiral_detector/
        ├── __init__.py
        ├── cli.py
        ├── config.py
        ├── logger.py
        ├── network.py
        ├── output.py
        ├── rdap.py
        ├── setup_cli.py
        ├── strategies/
        └── data/
            ├── systemd/
            │   ├── admiral-detector.service
            │   └── admiral-detector.timer
            └── integrations/
                └── pihole/
                    ├── 99-update-admiral-adlist.sh
                    ├── admiral-pihole-sync
                    ├── admiral-pihole-sync.path
                    └── admiral-pihole-sync.service
```

## Installation

Because the `systemd` daemon runs under the unprivileged `admiral` user (and with `ProtectHome=yes`), the runtime Python virtual environment is installed system-wide in `/opt/admiral_detector/.venv` rather than inside a user's home directory.

### Option 1: From a Local Git Checkout (`Makefile`)

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/admiral_detector.git
   cd admiral_detector
   ```

2. Run the interactive setup wizard (creates `/opt/admiral_detector/.venv`, installs `admiral_detector`, provisions the `admiral` system user, `/etc/admiral_detector/`, `systemd` units, and optional Pi-hole sync):
   ```bash
   sudo make setup
   ```

   Alternatively, run one of the non-interactive `Makefile` targets:
   ```bash
   sudo make setup-all          # Core detector + Pi-hole sync integration
   sudo make setup-detector     # Core detector service only
   sudo make setup-pihole-sync  # Add Pi-hole sync to an existing detector setup
   ```

To upgrade an existing installation after pulling new changes from git:
```bash
git pull
sudo make setup
```

### Option 2: Installed via a Dedicated Virtual Environment or System `pipx`

If installing from a built wheel or PyPI package without a local repository checkout:

```bash
sudo mkdir -p /opt/admiral_detector
sudo python3 -m venv /opt/admiral_detector/.venv
sudo /opt/admiral_detector/.venv/bin/pip install --upgrade pip
sudo /opt/admiral_detector/.venv/bin/pip install admiral-detector
sudo chmod -R a+rX /opt/admiral_detector
sudo /opt/admiral_detector/.venv/bin/admiral-detector-setup
```

Or using `pipx` configured to install into `/opt`:

```bash
sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install admiral-detector
sudo /usr/local/bin/admiral-detector-setup
```

## Configuration

During setup, a default configuration file is created at `/etc/admiral_detector/admiral_detector.conf` (`0640 root:admiral`) if one does not already exist. Reference templates are included in the repository root:

* `admiral_detector.conf.barebones.example` — minimal configuration for quick setup.
* `admiral_detector.conf.full.example` — all supported options, including custom request headers, user agents, HTTP/SOCKS proxies, redirect limits, regex ignore lists, and RDAP cache tuning.

> **Note:** If you replace `/etc/admiral_detector/admiral_detector.conf` with `admiral_detector.conf.barebones.example` while using Pi-hole sync, ensure `post_script_dir = /etc/admiral_detector/post.d/` is present under `[general]` so the post-scan hook executes.

## Usage & Service Management

### Ad-Hoc CLI Execution

```bash
admiral-detector --version
admiral-detector --help
admiral-detector -c /path/to/custom.conf
```

### Managing the `systemd` Service

Check timer schedule and service status:
```bash
systemctl status admiral-detector.timer
systemctl status admiral-detector.service
```

Trigger an immediate detection scan using the system configuration:
```bash
sudo systemctl start admiral-detector.service
```

View scan and Pi-hole sync logs:
```bash
journalctl -u admiral-detector.service -n 50 --no-pager
journalctl -u admiral-pihole-sync.service -n 50 --no-pager
```

## How Pi-hole Sync Works

When Pi-hole integration is enabled, domain updates flow across two privilege boundaries:

1. **Detection (`admiral` user):** `admiral-detector.service` writes JSON results to `/run/admiral_detector/detected_domains.json` and runs `/etc/admiral_detector/post.d/99-update-admiral-adlist.sh`, which atomically updates `/var/lib/admiral_detector/admiral_domains.list`.
2. **Path Activation (`root`):** `admiral-pihole-sync.path` monitors `/var/lib/admiral_detector/admiral_domains.list` via `inotify` and triggers `admiral-pihole-sync.service` (`/usr/local/sbin/admiral-pihole-sync`).
3. **Hybrid Blocking:**
   * `file:///var/lib/admiral_detector/admiral_domains.list` is registered as a Pi-hole adlist (`Admiral Detector domains`).
   * Any domain not yet compiled into `gravity.db` is validated with `pihole-FTL gravity checkList`, added to the wildcard denylist (`pihole denylist --wild -q`) with the comment `Admiral Detector staged`, and activated immediately via `pihole reloadlists`.
   * Once Pi-hole's scheduled weekly `pihole -g` run ingests the adlist into `gravity.db`, subsequent sync runs automatically remove the redundant staged denylist entries.

## Setup CLI Reference

`admiral-detector-setup` supports the following flags:

| Flag | Description |
| :--- | :--- |
| `-y`, `--non-interactive` | Run without prompts using defaults or explicit flags |
| `--bin-path <path>` | Explicitly specify the `admiral-detector` executable to symlink to `/usr/local/bin/admiral-detector` |
| `--with-pihole-sync` | Configure the Pi-hole adlist and denylist sync integration |
| `--without-pihole-sync` | Skip configuring the Pi-hole sync integration |
| `--pihole-sync-only` | Configure only the Pi-hole sync integration (assumes core detector is already installed) |
| `--run-now` | Trigger an immediate detection scan after setup completes |
| `--uninstall-pihole-sync` | Remove only the Pi-hole sync units, hook, helper, and `gravity.db` entries |
| `--uninstall` | Remove services, symlink, and Pi-hole integration while preserving `/etc/admiral_detector` and `/var/lib/admiral_detector` |
| `--purge` | Completely remove services, Pi-hole integration, configuration, state, logs, and the `admiral` system user |

## Uninstalling

Remove system services and Pi-hole entries while keeping your configuration and domain history:
```bash
sudo make uninstall
# or: sudo /opt/admiral_detector/.venv/bin/admiral-detector-setup -y --uninstall
```

Remove everything including configuration, cached RDAP data, logs, the `admiral` system user, and `/opt/admiral_detector`:
```bash
sudo make purge
```
*(If uninstalling without the `Makefile`, run `sudo /opt/admiral_detector/.venv/bin/admiral-detector-setup -y --purge` followed by `sudo rm -rf /opt/admiral_detector`.)*

## License

See [LICENSE](LICENSE) for details.