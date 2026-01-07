from netra.core.modules.base import BaseScanner
import subprocess
import json
import os
import asyncio

class GoScanner(BaseScanner):
    def __init__(self, binary_path="/app/bin/scout_bin"):
        super().__init__()
        self.name = "GoScanner"
        self.binary_path = binary_path
        self.chrome_url = os.getenv("CHROME_URL", "ws://chrome:9222")

    async def scan(self, target: str):
        """
        Executes the Go binary to scan the target using headless chrome.
        """
        if not os.path.exists(self.binary_path):
            return {"error": f"Go binary not found at {self.binary_path}"}

        try:
            # Construct command
            cmd = [
                self.binary_path,
                "-target", target,
                "-chrome-url", self.chrome_url
            ]
            
            # Run subprocess asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                return {"error": f"Go binary failed: {stderr.decode()}"}

            # Parse JSON output
            try:
                result = json.loads(stdout.decode())
                return result
            except json.JSONDecodeError:
                return {"error": f"Invalid JSON from Go: {stdout.decode()}"}

        except Exception as e:
            return {"error": str(e)}
