import re
import urllib.parse
from typing import Set, Tuple
import tldextract


class ExtractionStrategy:

    URL_REGEX = re.compile(
        r'(?:https?:)?//(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::(?P<port>\d{1,5}))?(?P<path>/[^\s"\'`<>)}\]\\]*)?',
        re.IGNORECASE,
    )
    BROAD_URL_REGEX = re.compile(
        r'https?://(?P<host>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::(?P<port>\d{1,5}))?(?P<path>/[^\s"\'`<>)}\]\\]*)?',
        re.IGNORECASE,
    )

    def __init__(self):
        self.tld_extractor = tldextract.TLDExtract(fallback_to_snapshot=True)

    def extract(self, html_body: str, publisher_url: str) -> Set[Tuple[str, str]]:
        raise NotImplementedError("Subclasses must implement extract()")

    def _normalise_script_text(self, raw_text: str, decode_passes: int = 3) -> str:
        text = raw_text.replace(r"\/", "/")
        for _ in range(decode_passes):
            text = urllib.parse.unquote(text)
        return text

    def get_apex_domain(self, raw_url_or_host: str) -> str:
        candidate = raw_url_or_host.strip()
        if(candidate.startswith("//")):
            candidate = f"https:{candidate}"
        if("://" in candidate):
            parsed = urllib.parse.urlsplit(candidate)
            hostname = parsed.hostname or ""
        else:
            hostname = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
            if(":" in hostname):
                hostname = hostname.split(":", 1)[0]

        ext = self.tld_extractor(hostname)
        if(ext.domain and ext.suffix):
            return f"{ext.domain}.{ext.suffix}".lower()
        return ""

    def _create_snippet(self, text: str, match: re.Match, padding: int = 40) -> str:
        start = max(0, match.start() - padding)
        end = min(len(text), match.end() + padding)
        snippet = text[start:end].replace("\n", " ").strip()
        return f"...{snippet}..."
