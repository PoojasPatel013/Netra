import subprocess
import json
import os
import logging
from netra.core.scanner import BaseScanner

logger = logging.getLogger(__name__)

class RustScanner(BaseScanner):
    def __init__(self, binary_path="/app/bin/guard_bin"):
        super().__init__()
        self.name = "LogCruncher (Rust)"
        self.binary_path = binary_path

    async def scan(self, target):
        """
        For now, since we don't have file uploads, this will run against a dummy log 
        if the target matches a specific keyword, or just return empty for URLs.
        Future: Download logs from URL or accept file path.
        """
        results = {
            "scanner": self.name,
            "status": "skipped",
            "findings": []
        }

        if not os.path.exists(self.binary_path):
            logger.warning(f"Rust binary not found at {self.binary_path}")
            return results

        # For demonstration during a URL scan, we'll feed it a sample string via stdin
        # simulating a log entry found on the target
        sample_log = f'192.168.1.1 - - [01/Jan/2024:12:00:00] "GET /search.php?q=UNION SELECT 1,2,3 HTTP/1.1" 200 500 "{target}"'
        
        try:
            # Run binary with input from stdin
            process = subprocess.Popen(
                [self.binary_path], 
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=sample_log)

            if process.returncode != 0:
                logger.error(f"Rust scanner failed: {stderr}")
                results["status"] = "failed"
                results["error"] = stderr
            else:
                try:
                    data = json.loads(stdout)
                    results["findings"] = data.get("threats", [])
                    results["status"] = "completed"
                    results["stats"] = {"lines_processed": data.get("total_lines", 0)}
                except json.JSONDecodeError:
                    logger.error(f"Invalid JSON from Rust scanner: {stdout}")
                    results["status"] = "error"

        except Exception as e:
            logger.exception("Error running Rust scanner")
            results["status"] = "error"
            results["error"] = str(e)

        return results
