import base64
import re
from typing import Set, Tuple
from bs4 import BeautifulSoup
from .base import ExtractionStrategy


class ObfuscatedInlineStrategy(ExtractionStrategy):

    BASE64_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

    def extract(self, html_body: str, publisher_url: str) -> Set[Tuple[str, str]]:
        pub_apex = self.get_apex_domain(publisher_url)
        candidates: Set[Tuple[str, str]] = set()
        soup = BeautifulSoup(html_body, "html.parser")

        for script_tag in soup.find_all("script"):
            if(not script_tag.has_attr("src") and script_tag.string):
                script_text = script_tag.string
                for b64_match in self.BASE64_REGEX.finditer(script_text):
                    try:
                        decoded = base64.b64decode(b64_match.group(0)).decode("utf-8", errors="ignore")
                        decoded = self._normalise_script_text(decoded, decode_passes=2)
                        for url_match in self.URL_REGEX.finditer(decoded):
                            apex = self.get_apex_domain(url_match.group("host"))
                            if(apex and apex != pub_apex):
                                snippet = self._create_snippet(decoded, url_match)
                                candidates.add((apex, f"Base64 Decoded: {snippet}"))
                    except Exception:
                        pass

        return candidates
