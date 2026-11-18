from .all_domains import AllDomainsStrategy
from .all_js_domains import AllJSDomainsStrategy
from .base import ExtractionStrategy
from .external import ExternalScriptStrategy
from .heuristic import BroadHeuristicStrategy
from .inline import InlineScriptStrategy
from .obfuscated import ObfuscatedInlineStrategy


def get_strategy(name: str) -> ExtractionStrategy:
    strategies = {
        "inline_script": InlineScriptStrategy,
        "obfuscated_inline": ObfuscatedInlineStrategy,
        "external_script": ExternalScriptStrategy,
        "broad_heuristic": BroadHeuristicStrategy,
        "all_domains": AllDomainsStrategy,
        "all_js_domains": AllJSDomainsStrategy,
    }
    strategy_cls = strategies.get(name, InlineScriptStrategy)
    return strategy_cls()
