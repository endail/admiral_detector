from typing import Set, Tuple
from bs4 import BeautifulSoup
from .base import ExtractionStrategy


class InlineScriptStrategy(ExtractionStrategy):

    ADMIRAL_MARKERS = ("__apNoHold", "decodeURI", "admiral", "leven", "atob(")

    def extract(self, html_body: str, publisher_url: str) -> Set[Tuple[str, str]]:
        pub_apex = self.get_apex_domain(publisher_url)
        candidates: Set[Tuple[str, str]] = set()

        decoded_body = self._normalise_script_text(html_body)
        soup = BeautifulSoup(decoded_body, "html.parser")

        for script_tag in soup.find_all("script"):
            if(not script_tag.has_attr("src") and script_tag.string):
                script_text = self._normalise_script_text(script_tag.string)
                if(any(marker in script_text for marker in self.ADMIRAL_MARKERS)):
                    for match in self.URL_REGEX.finditer(script_text):
                        apex = self.get_apex_domain(match.group("host"))
                        if(apex and apex != pub_apex):
                            snippet = self._create_snippet(script_text, match)
                            candidates.add((apex, snippet))

        return candidates
