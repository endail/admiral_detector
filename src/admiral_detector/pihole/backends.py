import abc
import logging
import os
import re
import sqlite3
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from .config import (
    PiHoleConfig,
    build_staged_comment,
    is_staged_comment,
)

logger = logging.getLogger("AdmiralDetector.PiHole")

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
WILDCARD_DOMAIN_TYPE = 3
WILDCARD_PREFIX = r"(\.|^)"
WILDCARD_SUFFIX = "$"


def domain_to_wildcard(domain: str) -> str:
    """Convert apex/subdomain into Pi-hole wildcard regex pattern."""
    return f"{WILDCARD_PREFIX}{re.escape(domain)}{WILDCARD_SUFFIX}"


def wildcard_to_domain(pattern: str) -> str:
    """Extract domain from Pi-hole wildcard regex pattern."""
    if(pattern.startswith(WILDCARD_PREFIX) and pattern.endswith(WILDCARD_SUFFIX)):
        inner = pattern[len(WILDCARD_PREFIX):-len(WILDCARD_SUFFIX)]
        return inner.replace(r"\.", ".")
    return pattern


class BasePiHoleBackend(abc.ABC):
    """Abstract interface for interacting with Pi-hole (local or remote)."""

    def __init__(self, config: PiHoleConfig):
        self.config = config

    @abc.abstractmethod
    def check_prerequisites(self) -> None:
        """Validate connectivity and requirements."""
        pass

    @abc.abstractmethod
    def ensure_adlist(self, adlist_uri: str, comment: str) -> bool:
        """Ensure the adlist URI is registered in Pi-hole. Returns True if newly added."""
        pass

    @abc.abstractmethod
    def get_compiled_domains(self, adlist_uri: str) -> Set[str]:
        """Fetch domains already compiled into gravity from this adlist."""
        pass

    @abc.abstractmethod
    def get_staged_domains(self) -> Dict[str, Any]:
        """Fetch currently active staged denylist domains. Returns {domain: metadata}."""
        pass

    @abc.abstractmethod
    def stage_domains(self, domains: List[str]) -> int:
        """Add domains to wildcard denylist with integrity-checked comments. Returns count."""
        pass

    @abc.abstractmethod
    def unstage_domains(self, domain_entries: List[Tuple[str, Any]]) -> int:
        """Remove domains from wildcard denylist. Returns count."""
        pass

    @abc.abstractmethod
    def reload_lists(self) -> None:
        """Tell Pi-hole to reload lists into memory."""
        pass

    def check_adlist_syntax(self, adlist_path: str) -> None:
        """Optional syntax validation using pihole-FTL."""
        pass


class LocalPiHoleBackend(BasePiHoleBackend):
    """Local Pi-hole backend using SQLite gravity.db and the official pihole CLI."""

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.config.gravity_db, timeout=30.0)
        conn.execute("PRAGMA busy_timeout = 30000")
        return conn

    def _run_cmd(self, cmd_args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        if(self.config.docker_container):
            full_cmd = ["docker", "exec", "-i", self.config.docker_container, *cmd_args]
        else:
            full_cmd = cmd_args

        return subprocess.run(full_cmd, capture_output=True, text=True, check=check)

    def check_prerequisites(self) -> None:
        if(not self.config.docker_container):
            if(not os.path.isfile(self.config.pihole_bin) or not os.access(self.config.pihole_bin, os.X_OK)):
                raise FileNotFoundError(f"Pi-hole CLI not found at: {self.config.pihole_bin}")
            if(not os.path.isfile(self.config.gravity_db)):
                raise FileNotFoundError(f"Pi-hole gravity database not found at: {self.config.gravity_db}")
        else:
            # Check docker availability
            res = subprocess.run(["docker", "ps", "-q", "-f", f"name={self.config.docker_container}"], capture_output=True)
            if(res.returncode != 0 or not res.stdout.strip()):
                raise RuntimeError(f"Docker container '{self.config.docker_container}' is not running.")

    def check_adlist_syntax(self, adlist_path: str) -> None:
        if(self.config.pihole_ftl_bin and os.path.isfile(self.config.pihole_ftl_bin) and os.access(self.config.pihole_ftl_bin, os.X_OK)):
            try:
                self._run_cmd([self.config.pihole_ftl_bin, "gravity", "checkList", adlist_path], check=False)
            except Exception as exc:
                logger.debug(f"pihole-FTL syntax check skipped: {exc}")

    def ensure_adlist(self, adlist_uri: str, comment: str) -> bool:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM adlist WHERE address = ?", (adlist_uri,))
            row = cursor.fetchone()
            if(row is not None):
                return False

            cursor.execute(
                "INSERT INTO adlist (address, enabled, comment) VALUES (?, 1, ?)",
                (adlist_uri, comment),
            )
            conn.commit()
            logger.info(f"Registered adlist in Pi-hole: {adlist_uri}")
            return True

    def get_compiled_domains(self, adlist_uri: str) -> Set[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM adlist WHERE address = ?", (adlist_uri,))
            row = cursor.fetchone()
            if(row is None):
                return set()

            adlist_id = int(row[0])
            cursor.execute("SELECT domain FROM gravity WHERE adlist_id = ?", (adlist_id,))
            return {str(r[0]).lower() for r in cursor.fetchall()}

    def get_staged_domains(self) -> Dict[str, Any]:
        staged: Dict[str, Any] = {}
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, domain, comment FROM domainlist WHERE type = ?",
                (WILDCARD_DOMAIN_TYPE,),
            )
            for row_id, pattern, comment in cursor.fetchall():
                domain = wildcard_to_domain(str(pattern)).lower()
                # Integrity check: verify comment hash matches domain
                if(is_staged_comment(comment, domain, self.config.comment_prefix)):
                    staged[domain] = {
                        "id": int(row_id),
                        "pattern": str(pattern),
                        "comment": comment,
                    }
        return staged

    def stage_domains(self, domains: List[str]) -> int:
        if(not domains):
            return 0

        # Process in batches to avoid command-line argument overflow
        batch_size = max(1, self.config.batch_size)
        total_staged = 0

        for i in range(0, len(domains), batch_size):
            chunk = domains[i:i + batch_size]
            # Use official pihole denylist command
            self._run_cmd([self.config.pihole_bin, "denylist", "--wild", "-q", *chunk], check=True)

            # Atomically update comment with domain integrity hash
            patterns_map = {domain_to_wildcard(d): build_staged_comment(d, self.config.comment_prefix) for d in chunk}
            with self._get_connection() as conn:
                for pattern, comment_str in patterns_map.items():
                    conn.execute(
                        "UPDATE domainlist SET comment = ? WHERE type = ? AND domain = ?",
                        (comment_str, WILDCARD_DOMAIN_TYPE, pattern),
                    )
                conn.commit()
            total_staged += len(chunk)

        logger.info(f"Staged {total_staged} new domain(s) in Pi-hole wildcard denylist.")
        return total_staged

    def unstage_domains(self, domain_entries: List[Tuple[str, Any]]) -> int:
        if(not domain_entries):
            return 0

        row_ids = [entry[1]["id"] for entry in domain_entries if "id" in entry[1]]
        if(not row_ids):
            return 0

        with self._get_connection() as conn:
            cursor = conn.cursor()
            placeholders = ",".join("?" for _ in row_ids)
            cursor.execute(f"DELETE FROM domainlist WHERE id IN ({placeholders})", row_ids)
            conn.commit()

        logger.info(f"Unstaged/cleaned up {len(row_ids)} domain(s) from Pi-hole denylist.")
        return len(row_ids)

    def reload_lists(self) -> None:
        self._run_cmd([self.config.pihole_bin, "reloadlists"], check=True)
        logger.info("Reloaded Pi-hole domain lists.")


class ApiPiHoleBackend(BasePiHoleBackend):
    """Remote Pi-hole backend using Pi-hole v6 REST API."""

    def __init__(self, config: PiHoleConfig):
        super().__init__(config)
        self._session_id: Optional[str] = self.config.api_token
        self._client = httpx.Client(
            base_url=self.config.api_url,
            timeout=self.config.api_timeout,
            verify=self.config.verify_ssl,
        )

    def _authenticate(self) -> None:
        if(self._session_id):
            return
        if(not self.config.api_password):
            return

        resp = self._client.post("/auth", json={"password": self.config.api_password})
        if(resp.status_code == 200):
            payload = resp.json()
            session = payload.get("session", {})
            self._session_id = session.get("sid")
            if(self._session_id):
                logger.debug("Successfully authenticated with Pi-hole v6 REST API.")
                return

        raise PermissionError(f"Failed to authenticate with Pi-hole API at {self.config.api_url}: {resp.text}")

    def _headers(self) -> Dict[str, str]:
        self._authenticate()
        headers = {"Accept": "application/json"}
        if(self._session_id):
            headers["X-FTL-SID"] = self._session_id
            headers["sid"] = self._session_id
        return headers

    def check_prerequisites(self) -> None:
        try:
            resp = self._client.get("/info", headers=self._headers())
            if(resp.status_code not in (200, 401)):
                # Try root API check
                resp = self._client.get("/", headers=self._headers())
        except Exception as exc:
            raise ConnectionError(f"Cannot reach Pi-hole API at {self.config.api_url}: {exc}") from exc

    def ensure_adlist(self, adlist_uri: str, comment: str) -> bool:
        try:
            resp = self._client.get("/lists", headers=self._headers())
            if(resp.status_code == 200):
                lists = resp.json().get("lists", [])
                for item in lists:
                    if(item.get("address") == adlist_uri):
                        return False
        except Exception:
            pass

        # Register adlist
        payload = {"address": adlist_uri, "type": "block", "comment": comment, "enabled": True}
        resp = self._client.post("/lists", json=payload, headers=self._headers())
        if(resp.status_code in (200, 201)):
            logger.info(f"Registered adlist in remote Pi-hole: {adlist_uri}")
            return True
        return False

    def get_compiled_domains(self, adlist_uri: str) -> Set[str]:
        # Gravity query via API endpoint if supported
        try:
            resp = self._client.get("/lists/gravity", headers=self._headers())
            if(resp.status_code == 200):
                data = resp.json()
                return {d.lower() for d in data.get("domains", [])}
        except Exception:
            pass
        return set()

    def get_staged_domains(self) -> Dict[str, Any]:
        staged: Dict[str, Any] = {}
        try:
            resp = self._client.get("/domains", params={"type": "deny_wildcard"}, headers=self._headers())
            if(resp.status_code == 200):
                items = resp.json().get("domains", [])
                for item in items:
                    domain = item.get("domain", "").lower()
                    comment = item.get("comment", "")
                    if(is_staged_comment(comment, domain, self.config.comment_prefix)):
                        staged[domain] = item
        except Exception as exc:
            logger.error(f"Error fetching staged domains from Pi-hole API: {exc}")
        return staged

    def stage_domains(self, domains: List[str]) -> int:
        count = 0
        for domain in domains:
            comment = build_staged_comment(domain, self.config.comment_prefix)
            payload = {
                "domain": domain,
                "type": "deny_wildcard",
                "comment": comment,
                "enabled": True,
            }
            resp = self._client.post("/domains", json=payload, headers=self._headers())
            if(resp.status_code in (200, 201)):
                count += 1
            else:
                logger.warning(f"Failed to stage domain {domain} via Pi-hole API: {resp.text}")
        return count

    def unstage_domains(self, domain_entries: List[Tuple[str, Any]]) -> int:
        count = 0
        for domain, details in domain_entries:
            item_id = details.get("id")
            if(item_id):
                endpoint = f"/domains/{item_id}"
            else:
                endpoint = f"/domains/{domain}"
            resp = self._client.delete(endpoint, headers=self._headers())
            if(resp.status_code in (200, 204)):
                count += 1
        return count

    def reload_lists(self) -> None:
        try:
            self._client.post("/action/restart/dnsmasq", headers=self._headers())
            logger.info("Triggered DNS reload via Pi-hole API.")
        except Exception as exc:
            logger.warning(f"Failed to trigger DNS reload via API: {exc}")


def get_backend(config: PiHoleConfig) -> BasePiHoleBackend:
    """Factory function returning appropriate backend instance."""
    if(config.mode == "api"):
        return ApiPiHoleBackend(config)
    return LocalPiHoleBackend(config)
