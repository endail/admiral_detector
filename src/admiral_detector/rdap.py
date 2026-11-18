import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from .network import create_http_client, use_dns

TARGET_ORGANISATIONS = {
    "leven labs",
    "level labs",
    "leven",
    "admiral",
    "copyrightaccesscontrol@levenlabs.com",
}

TARGET_ENTITY_ROLES = {"registrant", "administrative", "admin", "technical", "tech"}
TARGET_VCARD_FIELDS = {"fn", "org", "email"}

HTTP_STATUS_OK = 200
HTTP_STATUS_NOT_FOUND = 404
CACHEABLE_HTTP_STATUSES = {HTTP_STATUS_OK, HTTP_STATUS_NOT_FOUND}

DEFAULT_CACHE_TTL = 60 * 60 * 24 * 30
DEFAULT_CACHE_FILE = "/var/lib/admiral_detector/rdap_cache.json"
FALLBACK_CACHE_FILE = "/tmp/admiral_detector_rdap_cache.json"
RDAP_USER_AGENT = "AdmiralDetector/1.2"


class RDAPCache:

    def __init__(self, cache_file: str = DEFAULT_CACHE_FILE, ttl_seconds: int = DEFAULT_CACHE_TTL):
        self.ttl_seconds = ttl_seconds
        self.cache_file = self._resolve_writable_path(cache_file)
        self.cache = self._load_cache()

    def _resolve_writable_path(self, preferred_path: str) -> str:
        try:
            parent = os.path.dirname(os.path.abspath(preferred_path))
            os.makedirs(parent, exist_ok=True)
            if(os.access(parent, os.W_OK)):
                return preferred_path
        except Exception:
            pass
        return FALLBACK_CACHE_FILE

    def _load_cache(self) -> dict:
        if(os.path.exists(self.cache_file)):
            try:
                with open(self.cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_cache(self) -> None:
        try:
            with open(self.cache_file, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, indent=2)
        except Exception:
            pass

    def get(self, domain: str) -> Optional[Dict[str, Any]]:
        entry = self.cache.get(domain)
        if(entry and (time.time() - entry.get("timestamp", 0) < self.ttl_seconds)):
            return entry
        return None

    def set(self, domain: str, is_admiral: bool, details: Dict[str, Any]) -> None:
        self.cache[domain] = {
            "is_admiral": is_admiral,
            "timestamp": time.time(),
            "details": details,
        }
        self._save_cache()


def _extract_matching_entities(entities: list) -> List[str]:
    matches: List[str] = []

    for entity in entities:
        if(not isinstance(entity, dict)):
            continue

        roles = {str(r).lower() for r in entity.get("roles", [])}
        if(bool(roles.intersection(TARGET_ENTITY_ROLES)) or not roles):
            vcard_array = entity.get("vcardArray", [])
            if(len(vcard_array) > 1 and isinstance(vcard_array[1], list)):
                for item in vcard_array[1]:
                    if(isinstance(item, list) and len(item) >= 4):
                        field_type = str(item[0]).lower()
                        field_value = str(item[3]).strip()
                        field_lower = field_value.lower()
                        if(field_type in TARGET_VCARD_FIELDS):
                            for target in TARGET_ORGANISATIONS:
                                if(target in field_lower and field_value not in matches):
                                    matches.append(field_value)

        if("entities" in entity and isinstance(entity["entities"], list)):
            for nested in _extract_matching_entities(entity["entities"]):
                if(nested not in matches):
                    matches.append(nested)

    return matches


def verify_domain_rdap(
    domain: str,
    cache: RDAPCache,
    rdap_domain: str = "rdap.org",
    timeout: int = 10,
    max_redirects: int = 5,
    proxy: Optional[str] = None,
    dns: Optional[str] = None,
) -> Tuple[bool, Dict[str, Any]]:
    initial_url = f"https://{rdap_domain}/domain/{domain}"
    cached_entry = cache.get(domain)
    if(cached_entry is not None):
        cached_details = dict(cached_entry.get("details", {}))
        cached_details["from_cache"] = True
        return bool(cached_entry.get("is_admiral", False)), cached_details

    is_admiral = False
    details: Dict[str, Any] = {
        "initial_url": initial_url,
        "final_url": None,
        "redirect_chain": [],
        "http_status": None,
        "response_time_ms": None,
        "from_cache": False,
        "matched_entities": [],
        "error": None,
    }

    try:
        with use_dns(dns), create_http_client(
            timeout_seconds=timeout,
            max_redirects=max_redirects,
            proxy=proxy,
            verify_ssl=True,
        ) as client:
            response = client.get(initial_url, headers={"User-Agent": RDAP_USER_AGENT})
            final_url = str(response.url)
            all_urls = [str(r.url) for r in response.history] + [final_url]
            details["final_url"] = final_url
            details["redirect_chain"] = all_urls[1:]
            details["http_status"] = response.status_code
            details["response_time_ms"] = int(response.elapsed.total_seconds() * 1000)

            if(response.status_code == HTTP_STATUS_OK):
                data = response.json()
                matched = _extract_matching_entities(data.get("entities", []))
                details["matched_entities"] = matched
                if(matched):
                    is_admiral = True
            elif(response.status_code not in CACHEABLE_HTTP_STATUSES):
                details["error"] = f"Unexpected RDAP HTTP status: {response.status_code}"
    except Exception as error:
        details["error"] = str(error)

    if(details["error"] is None and details["http_status"] in CACHEABLE_HTTP_STATUSES):
        cache.set(domain, is_admiral, details)

    return is_admiral, details
