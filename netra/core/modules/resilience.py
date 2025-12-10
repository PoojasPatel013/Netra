import logging
import asyncio
import time
from typing import Dict, Any, List
from netra.core.scanner import BaseScanner
from netra.core.http import SafeHTTPClient

logger = logging.getLogger("netra.core.resilience")

class ResilienceScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Resilience: Rate Limit Verification and availability testing.
        """
        results = {
            "rate_limit_enabled": False,
            "threshold_tested": 0,
            "vulnerabilities": []
        }
        
        target = target if target.startswith("http") else f"http://{target}"
        base_url = target.rstrip("/")
        
        # Rate Limit Test
        # Send 30 requests in quick succession
        count = 30
        results["threshold_tested"] = count
        
        start_time = time.time()
        responses = []
        
        async with SafeHTTPClient() as client:
            tasks = []
            for _ in range(count):
                tasks.append(client.get(base_url, timeout=5))
            
            # Fire all at once
            resps = await asyncio.gather(*tasks, return_exceptions=True)
            
            status_codes = []
            for r in resps:
                if isinstance(r, Exception):
                     status_codes.append(0)
                else:
                     status_codes.append(r.status)
            
            # Analyze
            has_429 = 429 in status_codes
            has_403 = 403 in status_codes # sometimes WAF blocks as 403
            
            if has_429:
                results["rate_limit_enabled"] = True
                logger.info(f"Rate limit detected on {target}")
            elif has_403 and status_codes.count(403) > 5:
                 results["rate_limit_enabled"] = True
                 results["note"] = "Blocked via 403 (WAF)"
            else:
                 # If all checks passed (200), then no rate limit detected
                 success_count = status_codes.count(200)
                 if success_count > 25:
                      results["vulnerabilities"].append({
                          "type": "Missing Rate Limiting",
                          "severity": "Medium",
                          "details": f"Sent {count} requests in {round(time.time()-start_time, 2)}s and none were blocked.",
                          "impact": "Risk of DoS or Brute Force attacks."
                      })
                      
        return results
