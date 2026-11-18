from typing import Set, Tuple
from .base import ExtractionStrategy


class AllDomainsStrategy(ExtractionStrategy):

    def extract(self, html_body: str, publisher_url: str) -> Set[Tuple[str, str]]:
        pub_apex = self.get_apex_domain(publisher_url)
        candidates: Set[Tuple[str, str]] = set()

        for match in self.BROAD_URL_REGEX.finditer(html_body):
            apex = self.get_apex_domain(match.group("host"))
            if(apex and apex != pub_apex):
                snippet = self._create_snippet(html_body, match)
                candidates.add((apex, snippet))

        return candidates
