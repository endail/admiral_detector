from typing import Set, Tuple
from bs4 import BeautifulSoup
from .base import ExtractionStrategy


class ExternalScriptStrategy(ExtractionStrategy):

    def extract(self, html_body: str, publisher_url: str) -> Set[Tuple[str, str]]:
        pub_apex = self.get_apex_domain(publisher_url)
        candidates: Set[Tuple[str, str]] = set()
        soup = BeautifulSoup(html_body, "html.parser")

        for script_tag in soup.find_all("script"):
            if(script_tag.has_attr("src")):
                src = script_tag["src"]
                apex = self.get_apex_domain(src)
                if(apex and apex != pub_apex):
                    candidates.add((apex, str(script_tag)))

        return candidates
