import logging
import math
import re
from typing import Dict, Any, List
from netra.core.scanner import BaseScanner
from netra.core.http import SafeHTTPClient

logger = logging.getLogger("netra.core.iam")


class IAMScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        IAM Security: Session Auditors, OAuth Checks, MFA Gaps.
        """
        results = {
            "session_issues": [],
            "oauth_issues": [],
            "mfa_gaps": [],
            "analyzed_cookies": 0,
        }

        target = target if target.startswith("http") else f"http://{target}"

        async with SafeHTTPClient() as client:
            try:
                # 1. Session Analysis (Cookies)
                resp = await client.get(target, timeout=10)
                cookies = resp.cookies

                for key, morsel in cookies.items():
                    results["analyzed_cookies"] += 1
                    flags = []
                    if not morsel.get("secure") and target.startswith("https"):
                        flags.append("Missing Secure Flag")
                    if not morsel.get("httponly"):
                        flags.append("Missing HttpOnly Flag")
                    if not morsel.get("samesite"):
                        flags.append("Missing SameSite Attribute")

                    # Entropy Check
                    val = morsel.value
                    entropy = self.shannon_entropy(val)
                    if entropy < 3.0 and len(val) > 4:  # Low entropy session ID
                        flags.append(f"Weak Entropy ({round(entropy,2)})")

                    if flags:
                        results["session_issues"].append(
                            {"cookie": key, "issues": flags}
                        )

                # 2. OAuth Misconfig Search (Heuristic)
                html = await resp.text()
                # Find links with redirect_uri
                oauth_links = re.findall(r'href=["\'](.*redirect_uri=.*?)["\']', html)
                for link in oauth_links:
                    # Check for weak redirects
                    if "http://" in link and "https" not in link:
                        results["oauth_issues"].append(
                            {
                                "type": "Insecure OAuth Redirect",
                                "link": link[:50] + "...",
                            }
                        )
                    elif "localhost" in link:
                        results["oauth_issues"].append(
                            {
                                "type": "OAuth Redirect to Localhost (Debug Leak?)",
                                "link": link[:50] + "...",
                            }
                        )

                # 3. MFA Gap Analysis (Login Pages)
                # If we see a login form but no mentions of "MFA", "OTP", "2FA"
                if "password" in html.lower() and "login" in html.lower():
                    mfa_terms = ["mfa", "2fa", "otp", "authenticator", "second factor"]
                    has_mfa = any(term in html.lower() for term in mfa_terms)

                    if not has_mfa:
                        results["mfa_gaps"].append(
                            {
                                "url": target,
                                "details": "Login form detected without visible MFA controls.",
                            }
                        )

            except Exception as e:
                logger.error(f"IAM Scan failed: {e}")

        return results

    def shannon_entropy(self, data: str) -> float:
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy
