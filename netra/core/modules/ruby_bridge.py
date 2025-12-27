import subprocess
import json
import os
from typing import Dict, Any, List
from netra.core.scanner import BaseScanner


class RubyBridge:
    def __init__(self, scripts_dir: str = None):
        if scripts_dir:
            self.scripts_dir = scripts_dir
        else:
            # Default to netra/scans/ruby
            base_dir = os.path.dirname(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )
            self.scripts_dir = os.path.join(base_dir, "scans", "ruby")

    def execute_script(self, script_name: str, target: str) -> Dict[str, Any]:
        """
        Executes a ruby script and expects JSON output from stdout.
        """
        script_path = os.path.join(self.scripts_dir, script_name)
        if not os.path.exists(script_path):
            return {"error": f"Script {script_name} not found", "script": script_name}

        try:
            # Ruby scripts should accept target as ARGV[0] and print JSON to stdout
            cmd = ["ruby", script_path, target]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                return {
                    "error": "Execution failed",
                    "stderr": result.stderr,
                    "script": script_name,
                }

            try:
                data = json.loads(result.stdout)
                return data
            except json.JSONDecodeError:
                return {
                    "error": "Invalid JSON output",
                    "stdout": result.stdout,
                    "script": script_name,
                }

        except subprocess.TimeoutExpired:
            return {"error": "Timeout", "script": script_name}
        except Exception as e:
            return {"error": str(e), "script": script_name}

    def list_scripts(self) -> List[str]:
        if not os.path.exists(self.scripts_dir):
            return []
        return [f for f in os.listdir(self.scripts_dir) if f.endswith(".rb")]


class RubyScanner(BaseScanner):
    def __init__(self, script_name: str, name: str = None):
        self.script_name = script_name
        self.bridge = RubyBridge()
        self.name = name or f"RubyScanner_{script_name.replace('.rb', '')}"

    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Executes the Ruby script asynchronously via thread pool.
        """
        try:
            # Run blocking subprocess in a thread to keep asyncio loop happy
            import asyncio

            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(
                None, self.bridge.execute_script, self.script_name, target
            )
            return result
        except Exception as e:
            return {"error": str(e), "script": self.script_name}
