# admiral_detector

`admiral_detector` is a Python tool and `systemd` service that scans configured publisher websites to detect dynamically rotated Admiral (Leven Labs) anti-adblock domains, verifies domain registrations via RDAP, and outputs structured JSON metadata with optional post-run hooks and Pi-hole integration.

## Features

* **Interactive & Daemon Subcommands:** Run stateless ad-hoc scans directly in your terminal (`admiral-detector scan`) or run continuous production scans (`admiral-detector daemon`) with configurable scan intervals, randomized jitter, and startup delays controlled via the configuration file.
* **Modular Detection Strategies:** Extracts candidate anti-adblock domains from inline scripts, obfuscated payloads, external script references, and structural heuristics.
* **RDAP Verification & Caching:** Validates candidate domains against RDAP endpoints (such as `rdap.org` and registrar servers) with local JSON caching to avoid redundant lookups.
* **Privilege-Separated `systemd` Service:** Runs the continuous daemon service under a dedicated, unprivileged `admiral` system account with hardened `systemd` unit restrictions and dynamic SIGHUP configuration reload support.
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
            │   └── admiral-detector.service
            └── integrations/
                └── pihole/
                    ├── 99-update-admiral-adlist.sh
                    ├── admiral-pihole-sync
                    ├── admiral-pihole-sync.path
                    └── admiral-pihole-sync.service
```

## Installation

Because the `systemd` daemon runs under the unprivileged `admiral` user (with `ProtectHome=yes`), the runtime Python virtual environment is installed system-wide in `/opt/admiral_detector/.venv` rather than inside a user's home directory.

### Option 1: From a Local Git Checkout (`Makefile`)

1. Clone the repository:

   ```bash
   git clone https://github.com/endail/admiral_detector.git
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

If installing from a built wheel or package without a local repository checkout:

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

During setup, a system configuration file is created at `/etc/admiral_detector/admiral_detector.conf` (`0640 root:admiral`) if one does not already exist. Reference templates are included in the repository root:

* `admiral_detector.conf.barebones.example` — minimal configuration for quick setup.
* `admiral_detector.conf.full.example` — all supported options, including custom request headers, user agents, HTTP/SOCKS proxies, redirect limits, regex ignore lists, and RDAP cache tuning.

> **Note:** If you replace `/etc/admiral_detector/admiral_detector.conf` with `admiral_detector.conf.barebones.example` while using Pi-hole sync, ensure `post_script_dir = /etc/admiral_detector/post.d/` is present so the post-scan hook executes.

### Configuration Resolution Precedence

* **Ad-Hoc URL Scans (`scan <URL>` without `-c`):** Skips `/etc/admiral_detector/admiral_detector.conf` and `~/.config/` completely, using built-in defaults (`stdout` JSON output, `stderr` logging, user RDAP cache at `~/.cache/admiral_detector/rdap_cache.json`, and disabled post-scan hooks).
* **Explicit Config (`-c / --config <PATH>`):** Loads the specified INI file (such as `~/admiral.conf`), while allowing any accompanying CLI flags (`--url`, `--strategy`, `--output`, `--no-rdap`, `--proxy`) to override settings in memory.
* **Default Config Discovery (`scan` with neither URLs nor `-c`):** Checks `~/.config/admiral_detector/admiral_detector.conf` first, then falls back to `/etc/admiral_detector/admiral_detector.conf` if readable by the current user. Even when reading `/etc`, `scan` defaults output to `stdout` and suppresses `post.d/` hooks unless `--run-hooks` is passed.
* **Daemon Mode (`daemon -c <PATH>`):** Always requires an explicit `-c/--config` path, writes atomically to the configured output file, writes persistent logs to `/var/log/admiral_detector/`, and executes `post.d/` hooks.

## CLI Usage

### Subcommands Overview

| Subcommand | Purpose |
| :--- | :--- |
| `admiral-detector scan` | Run an interactive or ad-hoc scan against URLs or a config file (outputs JSON to `stdout` by default). |
| `admiral-detector daemon` | Run the continuous production scan daemon invoked by `admiral-detector.service`. |
| `admiral-detector strategies` | List all available detection strategy modules and their identifiers. |
| `admiral-detector check-config` | Validate an INI configuration file, regex ignore rules, and directory permissions. |
| `admiral-detector update-pihole-adlist` | Ingest detector JSON payload and update the local Pi-hole adlist file. |
| `admiral-detector pihole-sync` | Synchronise adlist and staged denylist with Pi-hole (local or remote REST API). |

*(Bare invocations whose first argument is a URL or scan flag automatically default to `admiral-detector scan`.)*

### Interactive & Ad-Hoc Scans (`scan`)

Scan one or more URLs directly and print JSON results to `stdout`:

```bash
admiral-detector scan https://example.com
# or using the bare shorthand:
admiral-detector https://example.com
```

Run specific strategies only, skip RDAP lookups for fast local parsing, and enable verbose debug logs on `stderr`:

```bash
admiral-detector scan -u https://example.com -s inline_script --no-rdap -v
```

Scan using a personal configuration file in your home directory:

```bash
admiral-detector scan -c ~/admiral.conf
```

Supported `scan` options:

* `URL` (positional) / `-u, --url <URL>` (repeatable) — Target publisher URL(s); overrides `[publishers]`.
* `-c, --config <PATH>` — Load baseline settings from an INI configuration file.
* `-s, --strategy <NAME>` (repeatable) — Restrict execution to the named strategy module(s).
* `-o, --output <PATH>` — Write JSON results to a file instead of `stdout` (`-`).
* `--no-rdap` — Skip RDAP domain registration verification.
* `--no-cache` — Bypass reading or writing `~/.cache/admiral_detector/rdap_cache.json`.
* `--proxy <URL>` — Route HTTP and RDAP requests through an HTTP/HTTPS proxy.
* `--run-hooks` — Opt-in flag to execute `post_script_dir` hooks after scanning (disabled by default in `scan`).
* `-v, --verbose` / `-q, --quiet` — Increase (`DEBUG`) or reduce (`ERROR`) log verbosity on `stderr`.

### Continuous Daemon & Timing Configuration (`daemon`)

In daemon mode, `admiral-detector` runs as a continuous background service whose timing cadence is configured directly in the INI configuration file under `[daemon]`:

```ini
[daemon]
# Scan interval: e.g. 1h, 30m, 3600s
interval = 1h

# Randomized jitter delay added to interval: e.g. 5m, 300s, 0s to disable
random_delay = 5m

# Initial delay before the first scan iteration on startup: e.g. 0s, 3min
initial_delay = 0s
```

Run the continuous daemon (used by `admiral-detector.service`):

```bash
admiral-detector daemon -c /etc/admiral_detector/admiral_detector.conf
```

Test a single iteration safely as the `admiral` user without writing state files or triggering Pi-hole hooks:

```bash
sudo -u admiral admiral-detector daemon -c /etc/admiral_detector/admiral_detector.conf --dry-run
```

Run a single scan iteration with production file outputs and hooks without looping:

```bash
admiral-detector daemon -c /etc/admiral_detector/admiral_detector.conf --once
```

Temporarily override the scan interval via CLI:

```bash
admiral-detector daemon -c /etc/admiral_detector/admiral_detector.conf --interval 30m
```

The daemon responds to:
* **`SIGTERM` / `SIGINT`:** Gracefully finishes the current scan cycle or sleep and terminates cleanly (exit code 0).
* **`SIGHUP` (or file modification):** Automatically detects modified configuration on disk or upon receiving `SIGHUP` (`systemctl reload admiral-detector.service`), immediately reloads configuration, and starts a fresh scan cycle.

### Inspecting Strategies & Validating Configs

List registered detection strategies:

```bash
admiral-detector strategies
admiral-detector strategies --json
```

Validate configuration syntax, timing options, ignore regexes, and path permissions before reloading the service:

```bash
admiral-detector check-config -c ~/admiral.conf
sudo admiral-detector check-config -c /etc/admiral_detector/admiral_detector.conf
```

## Managing the `systemd` Service

Check service status:

```bash
systemctl status admiral-detector.service
```

Restart the service:

```bash
sudo systemctl restart admiral-detector.service
```

Reload configuration on the fly without stopping the daemon:

```bash
sudo systemctl reload admiral-detector.service
```

View daemon and Pi-hole sync logs:

```bash
journalctl -u admiral-detector.service -n 50 --no-pager
journalctl -u admiral-pihole-sync.service -n 50 --no-pager
```

## How Pi-hole Sync Works

When Pi-hole integration is enabled, domain updates flow across two privilege boundaries with full integrity hashing and backend abstraction:

1. **Detection (`admiral` user):** `admiral-detector.service` writes JSON results to `/run/admiral_detector/detected_domains.json` and invokes `/etc/admiral_detector/post.d/99-update-admiral-adlist.sh`, which calls `admiral-detector update-pihole-adlist` to atomically update `/var/lib/admiral_detector/admiral_domains.list`.
2. **Path Activation (`root`):** `admiral-pihole-sync.path` monitors `/var/lib/admiral_detector/admiral_domains.list` via `inotify` and triggers `admiral-pihole-sync.service` (`/usr/local/sbin/admiral-pihole-sync` or `admiral-detector pihole-sync`).
3. **Synchronization & Integrity-Checked Hybrid Blocking:**
   * Configured via `/etc/admiral_detector/pihole.conf` (see [pihole.conf.example](pihole.conf.example)).
   * **Local Backend:** Operates directly against local Pi-hole installations (bare-metal or Docker via `docker_container = pihole`), querying `gravity.db` with WAL busy timeouts and staging domains using official `pihole denylist --wild` CLI batches.
   * **Remote API Backend:** Communicates directly with remote Pi-hole v6 instances over HTTPS via the official Pi-hole v6 REST API (`/api/domains`, `/api/lists`).
   * **Integrity Hashing:** Staged denylist entries are labeled with a domain integrity hash:
     ```text
     admiral_detector:staged:<sha256(domain)[:16]>
     ```
     This binds each denylist entry cryptographically to its domain name, preventing accidental removal or collision with user-managed denylist rules.
   * **Zero-Rebuild Instant Blocking:** Uncompiled domains are immediately activated in the wildcard denylist and loaded with `pihole reloadlists`. Once Pi-hole's weekly gravity run (`pihole -g`) compiles the local adlist into `gravity.db`, subsequent sync runs automatically unstage the redundant denylist entries.
   * **Concurrency Protection:** Uses non-blocking `flock` locking (`/run/admiral_detector/pihole-sync.lock`) to prevent race conditions during rapid or manual CLI runs.

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