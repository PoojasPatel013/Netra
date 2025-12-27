from typing import Dict, Any, List


class ComplianceEngine:
    def __init__(self):
        self.standards = {
            "PCI-DSS": {"name": "PCI-DSS v4.0", "violations": []},
            "HIPAA": {"name": "HIPAA Security Rule", "violations": []},
            "GDPR": {"name": "GDPR (EU) 2016/679", "violations": []},
            "NIST": {"name": "NIST SP 800-53", "violations": []},
        }

    def enrich_report(self, results: Dict[str, Any]):
        """
        Analyzes the scan results and appends a 'compliance' section.
        """
        self._analyze_ports(results)
        self._analyze_cloud(results)
        self._analyze_web_vulns(results)
        self._analyze_ruby_findings(results)

        # Summarize
        summary = {}
        for key, std in self.standards.items():
            if std["violations"]:
                summary[key] = std

        results["compliance"] = summary
        return results

    def _add_violation(
        self, standard: str, section: str, description: str, severity: str = "High"
    ):
        self.standards[standard]["violations"].append(
            {"section": section, "description": description, "severity": severity}
        )

    def _analyze_ports(self, results: Dict[str, Any]):
        # Analyze PortScanner or RubyScanner_banner_grabber
        ports = []
        if "PortScanner" in results and "open_ports" in results["PortScanner"]:
            ports = results["PortScanner"]["open_ports"]
        elif "RubyScanner_banner_grabber" in results:  # Ruby Bridge Fallback
            ports = results["RubyScanner_banner_grabber"].get("open_ports", [])

        # Telnet (23) -> PCI + NIST
        if 23 in ports:
            self._add_violation(
                "PCI-DSS", "2.2.3", "Insecure service (Telnet) enabled.", "High"
            )
            self._add_violation(
                "NIST", "CM-7", "Least Functionality - Insecure Service", "Medium"
            )

        # FTP (21) -> PCI
        if 21 in ports:
            self._add_violation(
                "PCI-DSS",
                "2.2.2",
                "Insecure service (FTP) enabled. Use SFTP.",
                "Medium",
            )

    def _analyze_cloud(self, results: Dict[str, Any]):
        # CloudScanner findings
        if "CloudScanner" not in results:
            return

        buckets = results["CloudScanner"].get("buckets", [])
        if buckets:
            self._add_violation(
                "HIPAA",
                "164.312(a)(1)",
                "Access Control: Public Cloud Storage detected containing potential PHI.",
                "Critical",
            )
            self._add_violation(
                "GDPR",
                "Art 32",
                "Inadequate encryption/protection of personal data storage.",
                "High",
            )
            self._add_violation(
                "NIST", "AC-3", "Access Enforcement - Public Storage", "High"
            )

    def _analyze_web_vulns(self, results: Dict[str, Any]):
        # Check ThreatScanner (Ruby) or others
        vulns = []
        if "ThreatScanner" in results:
            vulns.extend(results["ThreatScanner"].get("vulnerabilities", []))

        for v in vulns:
            v_type = v.get("type", "").lower()

            if "spf" in v_type or "dmarc" in v_type:
                self._add_violation(
                    "NIST",
                    "SI-8",
                    "Spam Protection - Email Authentication Missing",
                    "Low",
                )

            if "robots.txt" in v_type and "sensitive" in v_type:
                self._add_violation(
                    "NIST",
                    "RA-5",
                    "Vulnerability Monitoring - Information Disclosure",
                    "Low",
                )

    def _analyze_ruby_findings(self, results: Dict[str, Any]):
        # IAM / Cookies
        if "IAMScanner" in results:
            vulns = results["IAMScanner"].get("vulnerabilities", [])
            for v in vulns:
                detail = v.get("details", "").lower()
                if "secure flag" in detail:
                    self._add_violation(
                        "PCI-DSS",
                        "8.2.1",
                        "Transmission of authentication credentials over insecure channel.",
                        "High",
                    )
                if "httponly" in detail:
                    self._add_violation(
                        "OWASP-Top10",
                        "A05:2021",
                        "Security Misconfiguration - Missing HttpOnly",
                        "Medium",
                    )
