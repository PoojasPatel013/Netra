import logging
import tldextract
from typing import Dict, Any, List, Set
from netra.core.scanner import BaseScanner
from netra.core.http import SafeHTTPClient

logger = logging.getLogger("netra.core.acquisition")


class AcquisitionScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Acquisition Mapping: Finds subsidiary or related companies/domains
        by analyzing Subject Alternative Names (SANs) in certificates.
        """
        results = {"acquisitions": [], "related_domains": [], "count": 0}

        # Extract main domain (e.g. google.com -> google)
        ext = tldextract.extract(target)
        root_domain = f"{ext.domain}.{ext.suffix}"

        # We query crt.sh again, but focus on finding *different* root domains
        url = f"https://crt.sh/?q=%25.{root_domain}&output=json"

        logger.info(f"Mapping acquisitions for {root_domain}...")

        try:
            async with SafeHTTPClient() as client:
                response = await client.get(url, timeout=20)

                if response.status == 200:
                    data = await response.json()
                    related_roots: Set[str] = set()

                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower()
                            if not name:
                                continue

                            # Extract root of this SAN
                            san_ext = tldextract.extract(name)
                            san_root = f"{san_ext.domain}.{san_ext.suffix}"

                            # If it's a valid domain AND different from our target root
                            if (
                                san_ext.domain
                                and san_ext.suffix
                                and san_root != root_domain
                            ):
                                related_roots.add(san_root)

                    # Filter out obvious trash or wildcards
                    clean_roots = [r for r in related_roots if "*" not in r]

                    results["related_domains"] = sorted(clean_roots)
                    results["count"] = len(clean_roots)

                    # Heuristic: If it shares a cert, it's likely an acquisition or sibling brand
                    results["acquisitions"] = [
                        {"domain": r, "confidence": "High (Shared Cert)"}
                        for r in clean_roots
                    ]

                    logger.info(f"Found {results['count']} related domains via SANs.")

                else:
                    results["error"] = f"crt.sh returned {response.status}"

        except Exception as e:
            logger.error(f"Acquisition scan failed: {e}")
            results["error"] = str(e)

        return results
