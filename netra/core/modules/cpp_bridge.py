from netra.core.scanner import BaseScanner
import subprocess
import json
import os
import asyncio
import logging

logger = logging.getLogger(__name__)

class GhostScanner(BaseScanner):
    def __init__(self, binary_path="/app/ghost/vortex_agent"):
        super().__init__()
        self.name = "GhostScanner (C++)"
        self.binary_path = binary_path

    async def scan(self, target: str):
        """
        Executes the C++ VortexAgent binary.
        """
        results = {
            "scanner": self.name,
            "status": "skipped",
            "findings": []
        }

        # Check binary existence
        if not os.path.exists(self.binary_path):
             # For dev/test, fallback to a mocked response if we are just testing logic
             logger.warning(f"VortexAgent binary not found at {self.binary_path}")
             return {"error": f"Binary not found: {self.binary_path}"}

        try:
            # Run C++ Binary
            process = await asyncio.create_subprocess_exec(
                self.binary_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"error": f"Agent failed: {stderr.decode()}"}

            # Parse JSON output
            try:
                data = json.loads(stdout.decode())
                
                # Transform Agent Data into Findings
                if "processes" in data:
                    results["findings"].append({
                        "type": "System Intelligence",
                        "severity": "Info",
                        "description": f"Target OS: {data.get('os')} | User: {data.get('user')}",
                        "data": data["processes"]
                    })
                
                results["status"] = "completed"
                return results

            except json.JSONDecodeError:
                return {"error": f"Invalid JSON from Agent: {stdout.decode()}"}

        except Exception as e:
            return {"error": str(e)}
