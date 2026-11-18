# Admiral Detector

A modular, proactive detector for Admiral (Leven Labs) dynamic anti-adblock domains.

`admiral_detector` fetches configured publisher URLs, extracts candidate third-party domains using one or more configurable parsing strategies, optionally verifies domain ownership via RDAP (with persistent caching and full redirect telemetry), writes a structured JSON report to an ephemeral RAM disk (`/run/admiral_detector/detected_domains.json`), and triggers executable post-processing hooks in `/etc/admiral_detector/post.d/`.

---

## Installation & Upgrading

### Fresh Installation (Virtual Environment)
```bash
python3 build_admiral_detector.py
cd admiral_detector
python3 -m venv .venv
.venv/bin/pip install -e .
```

### Replacing an Existing `admiral-blocker` Installation
```bash
# 1. Uninstall the old package from your existing virtual environment
~/projects/admiral_blocker/.venv/bin/pip uninstall -y admiral-blocker

# 2. Generate and install admiral_detector in a clean project directory
mkdir -p ~/projects && cd ~/projects
python3 /path/to/build_admiral_detector.py
cd admiral_detector
python3 -m venv .venv
.venv/bin/pip install -e .
```

---

## Usage

```bash
admiral-detector -c /etc/admiral_detector/admiral_detector.conf
```

### CLI Options
- `-c`, `--config`: Path to the INI configuration file (default: `/etc/admiral_detector/admiral_detector.conf`).
- `-v`, `--version`: Print the installed `admiral_detector` package version and exit.

---

## Configuration Reference

Configuration uses standard INI syntax (`key = value`). Two reference templates are included in the root project directory:
- `admiral_detector.conf.barebones.example` — minimal working setup relying on built-in defaults.
- `admiral_detector.conf.full.example` — exhaustive reference documenting all sections and options.

### `[general]` Section

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `output_file` | string | `/run/admiral_detector/detected_domains.json` | Destination path for the structured JSON detection report. Set empty (`output_file =`) to disable JSON output. |
| `post_script_dir` | string | `None` | Directory of executable hook scripts invoked in lexical order with `output_file` passed as `$1`. |

### `[defaults]` Section

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `strategy` | CSV | `inline_script` | Comma-separated list of extraction strategies applied to publishers without an explicit `strategy`. |
| `ignore_domains` | CSV | `""` | Comma-separated apex domains or `regex:<pattern>` rules ignored globally unless overridden by a publisher. |
| `header_<Name>` | string | Chrome `User-Agent` | Default custom HTTP header applied to all requests (e.g., `header_user_agent`, `header_accept-encoding`). Header names are normalised to canonical `Title-Case` (such as `User-Agent` and `Accept-Encoding`) and overridden case-insensitively by profile or publisher headers. |

### `[rdap]` Section

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `verify` | bool | `false` | Whether to verify extracted domains against RDAP registration records (`Leven Labs` / `Admiral`). |
| `domain` | string | `rdap.org` | Bootstrap RDAP server hostname queried via `https://<domain>/domain/<apex>`. |
| `cache_file` | string | `/var/lib/admiral_detector/rdap_cache.json` | Persistent JSON cache for RDAP lookup results (falls back to `/tmp/admiral_detector_rdap_cache.json` if unwritable). |
| `cache_ttl_seconds` | int | `2592000` | Time-to-live for cached RDAP results in seconds (default: 30 days). Transient network or HTTP errors are never cached. |

### `[network]` Section

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `timeout_seconds` | int | `15` | Maximum request timeout in seconds for HTTP and RDAP requests. |
| `max_redirects` | int | `5` | Maximum HTTP redirects to follow per request. |
| `proxy` | string | `None` | Optional HTTP/SOCKS proxy URL (e.g., `http://127.0.0.1:8080`). |
| `dns` | string | `None` | Optional custom DNS resolver IP (e.g., `1.1.1.1` or `1.1.1.1:5353`) used for hostname resolution while preserving TLS SNI. |
| `allow_insecure` | bool | `false` | Allow plaintext `http://` URLs and disable strict TLS certificate verification on publisher fetches. |

### `[logging]` Section

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `level` | string | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `file` | string | `None` | Optional file path for persistent log output in addition to stdout. |

### `[profiles]` and `[profile:<name>]` Sections
Define reusable sets of HTTP headers to avoid repetition across multiple `[publisher:<name>]` sections:

```ini
[profiles]
[profile:desktop_chrome]
header_user_agent = Mozilla/5.0 ...
header_accept-language = en-AU,en-US;q=0.9,en;q=0.8
```

Reference a profile inside any `[publisher:<name>]` section with `profile = desktop_chrome`. Headers in a profile override `[defaults]` case-insensitively (with canonical `Title-Case` header names), and headers defined directly inside `[publisher:<name>]` override the profile.

### `[publishers]` Section
A simple newline-separated list of target URLs or bare domains (bare domains automatically assume `https://`). Query strings containing `=` and explicit ports (e.g., `https://example.com:8443/path?a=1`) are preserved intact. All entries in `[publishers]` inherit `[defaults]`, `[rdap]`, and `[network]`.

### `[publisher:<name>]` Sections
Per-publisher configuration supporting isolated overrides of global defaults (overrides apply strictly to that publisher and never persist to subsequent publishers):

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `url` | string | *(required)* | Target URL or bare domain (with optional `:port`, path, and query string). |
| `strategy` | CSV | `[defaults]` `strategy` | Comma-separated list of extraction strategies for this publisher. |
| `ignore_domains` | CSV | `[defaults]` `ignore_domains` | Replaces `[defaults]` `ignore_domains` for this publisher only. Set empty (`ignore_domains =`) to ignore nothing. |
| `profile` | string | `None` | Name of a `[profile:<name>]` header set to layer over `[defaults]`. |
| `verify_rdap` | bool | `[rdap]` `verify` | Overrides RDAP verification for this publisher (`verify` is also accepted). |
| `rdap_domain` | string | `[rdap]` `domain` | Overrides the RDAP bootstrap server hostname for this publisher. |
| `timeout_seconds` | int | `[network]` `timeout_seconds` | Overrides request timeout in seconds for this publisher. |
| `max_redirects` | int | `[network]` `max_redirects` | Overrides maximum redirects for this publisher. |
| `proxy` | string | `[network]` `proxy` | Overrides proxy URL for this publisher. Set empty (`proxy =`) to bypass a global proxy. |
| `dns` | string | `[network]` `dns` | Overrides custom DNS resolver for this publisher. Set empty (`dns =`) to use system DNS. |
| `allow_insecure` | bool | `[network]` `allow_insecure` | Overrides plaintext HTTP allowance and TLS certificate verification for this publisher. |
| `header_<Name>` | string | — | Publisher-specific HTTP header override (highest precedence). |

---

## Extraction Strategies

- `inline_script`: Inspects inline `<script>` blocks containing Admiral loader markers (`__apNoHold`, `decodeURI`, `admiral`, `leven`, `atob(`) and extracts third-party apex domains from URLs (supporting `.js`, extensionless paths, ports, query strings, fragments, and escaped slashes).
- `all_js_domains`: Extracts all third-party apex domains referenced across any inline `<script>` tag on the page.
- `obfuscated_inline`: Decodes Base64 blobs inside inline `<script>` tags and extracts embedded third-party apex domains.
- `external_script`: Extracts apex domains from `<script src="...">` tags.
- `broad_heuristic`: Multi-pass URI-decodes the entire HTML document and extracts all third-party HTTP(S) apex domains.
- `all_domains`: Scans the raw HTML document for all third-party HTTP(S) apex domains.

Multiple strategies can be combined as a comma-separated list (for example, `strategy = inline_script, obfuscated_inline`). The page is fetched once, all configured strategies run against the response, and extracted apex domains are deduplicated while recording which strategies matched each domain in `matched_strategies`.

---

## URL Validation & Protocol Rules

- Bare domains without a scheme (e.g., `techcrunch.com` or `example.com:8443/news`) automatically assume `https://`.
- Explicit ports (e.g., `https://www.google.com:8080`) are supported and preserved.
- Plaintext `http://` URLs are rejected by default unless `allow_insecure = true` is set in `[network]` or on that publisher section (which permits the URL, disables strict TLS verification for that target, and logs a warning).
- Non-HTTP(S) schemes (`file://`, `ftp://`, `javascript:`, `data:`, etc.) are unconditionally rejected.
