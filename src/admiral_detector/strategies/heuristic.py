from typing import Set, Tuple
from .base import ExtractionStrategy


class BroadHeuristicStrategy(ExtractionStrategy):

    def extract(self, html_body: str, publisher_url: str) -> Set[Tuple[str, str]]:
        pub_apex = self.get_apex_domain(publisher_url)
        candidates: Set[Tuple[str, str]] = set()

        decoded_body = self._normalise_script_text(html_body)
        for match in self.BROAD_URL_REGEX.finditer(decoded_body):
            apex = self.get_apex_domain(match.group("host"))
            if(apex and apex != pub_apex):
                snippet = self._create_snippet(decoded_body, match)
                candidates.add((apex, snippet))

        return candidates
