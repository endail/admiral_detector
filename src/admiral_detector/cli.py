import argparse
import datetime
import re
import sys
import time
from typing import Any, Dict, List, Set

from . import __version__ as FALLBACK_VERSION
from .config import load_config
from .logger import setup_logger
from .network import create_http_client, use_dns
from .output import run_post_scripts, write_json_output
from .rdap import RDAPCache, verify_domain_rdap
from .strategies.factory import get_strategy

try:
    from importlib.metadata import version

    PKG_VERSION = version("admiral_detector")
except Exception:
    PKG_VERSION = FALLBACK_VERSION

DEFAULT_CONFIG_PATH = "/etc/admiral_detector/admiral_detector.conf"


def is_ignored(domain: str, ignore_domains: Set[str], ignore_regexes: List[re.Pattern]) -> bool:
    if(domain in ignore_domains):
        return True
    for regex in ignore_regexes:
        if(regex.search(domain)):
            return True
    return False


def main():
    start_time = time.time()
    parser = argparse.ArgumentParser(description="Admiral/Leven Labs Proactive Domain Detector")
    parser.add_argument(
        "-c",
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to config file",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"admiral_detector {PKG_VERSION}",
    )
    args = parser.parse_args()

    try:
        targets, global_opts = load_config(args.config)
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

    logger = setup_logger(global_opts["log_level"], global_opts["log_file"])
    logger.info(f"Starting admiral_detector v{PKG_VERSION}")

    for cfg_warn in global_opts.get("config_warnings", []):
        logger.warning(cfg_warn)
    for cfg_err in global_opts.get("config_errors", []):
        logger.error(cfg_err)

    rdap_cache = RDAPCache(
        cache_file=global_opts["rdap_cache_file"],
        ttl_seconds=global_opts["rdap_cache_ttl_seconds"],
    )
    results = []
    total_unique_domains: Set[str] = set()

    for target in targets:
        for warn in target.warnings:
            logger.warning(warn)

        strategies_label = ", ".join(target.strategies)
        logger.info(
            f"Scanning: {target.url} [Strategies: {strategies_label}, Profile: {target.profile or 'none'}]"
        )
        target_result = {
            "publisher": target.name,
            "profile": target.profile,
            "initial_url": target.url,
            "strategies": target.strategies,
            "date_detected": datetime.datetime.now().isoformat(),
            "network": {
                "initial_url": target.url,
                "final_url": None,
                "redirect_chain": [],
                "http_status": None,
                "response_time_ms": None,
                "proxy_used": target.proxy,
                "dns_used": target.dns,
                "tls_verified": not target.allow_insecure,
                "headers_sent": target.headers,
            },
            "extracted_domains": [],
            "rdap_rejected_domains": [],
            "ignored_domains": [],
            "error": None,
        }

        try:
            with use_dns(target.dns), create_http_client(
                timeout_seconds=target.timeout_seconds,
                max_redirects=target.max_redirects,
                proxy=target.proxy,
                verify_ssl=not target.allow_insecure,
            ) as client:
                resp = client.get(target.url, headers=target.headers)
                html_body = resp.text
                final_url = str(resp.url)
                all_urls = [str(r.url) for r in resp.history] + [final_url]
                redirect_chain = all_urls[1:]

                target_result["network"].update(
                    {
                        "final_url": final_url,
                        "redirect_chain": redirect_chain,
                        "http_status": resp.status_code,
                        "response_time_ms": int(resp.elapsed.total_seconds() * 1000),
                    }
                )

            logger.debug(
                f"HTTP {resp.status_code} received from final URL: {final_url} "
                f"(redirects: {len(redirect_chain)})"
            )

            merged_extractions: Dict[str, Dict[str, Any]] = {}
            for strategy_name in target.strategies:
                strategy = get_strategy(strategy_name)
                extractions = strategy.extract(html_body, final_url)
                for domain, snippet in sorted(extractions):
                    if(domain not in merged_extractions):
                        merged_extractions[domain] = {
                            "snippet": snippet,
                            "matched_strategies": [strategy_name],
                        }
                    elif(strategy_name not in merged_extractions[domain]["matched_strategies"]):
                        merged_extractions[domain]["matched_strategies"].append(strategy_name)

            for domain in sorted(merged_extractions.keys()):
                entry_info = merged_extractions[domain]
                snippet = entry_info["snippet"]
                matched_strategies = entry_info["matched_strategies"]

                if(is_ignored(domain, target.ignore_domains, target.ignore_regexes)):
                    logger.debug(f"Ignored: {domain} (matched ignore list)")
                    target_result["ignored_domains"].append(domain)
                    continue

                if(target.verify_rdap):
                    is_admiral, rdap_details = verify_domain_rdap(
                        domain=domain,
                        cache=rdap_cache,
                        rdap_domain=target.rdap_domain,
                        timeout=target.timeout_seconds,
                        max_redirects=target.max_redirects,
                        proxy=target.proxy,
                        dns=target.dns,
                    )
                    if(is_admiral):
                        total_unique_domains.add(domain)
                        logger.info(f"Detected [RDAP Verified]: {domain}")
                        logger.debug(f"Context: {snippet}")
                        target_result["extracted_domains"].append(
                            {
                                "domain": domain,
                                "matched_strategies": matched_strategies,
                                "context_snippet": snippet,
                                "rdap_verified": True,
                                "rdap_details": rdap_details,
                            }
                        )
                    else:
                        logger.debug(f"RDAP Rejected: {domain}")
                        target_result["rdap_rejected_domains"].append(
                            {
                                "domain": domain,
                                "matched_strategies": matched_strategies,
                                "context_snippet": snippet,
                                "rdap_verified": False,
                                "rdap_details": rdap_details,
                            }
                        )
                else:
                    total_unique_domains.add(domain)
                    logger.info(f"Detected: {domain}")
                    logger.debug(f"Context: {snippet}")
                    target_result["extracted_domains"].append(
                        {
                            "domain": domain,
                            "matched_strategies": matched_strategies,
                            "context_snippet": snippet,
                            "rdap_verified": None,
                            "rdap_details": None,
                        }
                    )

        except Exception as error:
            logger.error(f"Error fetching {target.url}: {error}")
            target_result["error"] = str(error)

        results.append(target_result)

    duration = time.time() - start_time
    json_payload = {
        "metadata": {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": PKG_VERSION,
            "duration_seconds": round(duration, 2),
            "total_publishers_scanned": len(targets),
            "unique_domains": sorted(list(total_unique_domains)),
        },
        "results": results,
    }

    if(global_opts["output_file"]):
        write_json_output(json_payload, global_opts["output_file"])
        if(global_opts["post_script_dir"]):
            run_post_scripts(global_opts["post_script_dir"], global_opts["output_file"])


if(__name__ == "__main__"):
    main()
