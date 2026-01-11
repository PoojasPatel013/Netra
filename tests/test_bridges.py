import unittest
from unittest.mock import patch, MagicMock
import asyncio
import json
from netra.core.modules.rust_bridge import RustScanner
from netra.core.modules.go_bridge import GoScanner

class TestBridges(unittest.TestCase):
    
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    @patch('subprocess.run')
    def test_rust_scanner(self, mock_run):
        # Setup Mock
        mock_output = {
            "file": "test.log",
            "threats": [
                {"type": "SQL Injection", "line": 10, "content": "UNION SELECT"}
            ]
        }
        
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(mock_output)
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        # Execute
        scanner = RustScanner()
        # Since scan is async, we need to run it in the loop
        result = self.loop.run_until_complete(scanner.scan("test_target"))

        # Assertions
        self.assertIn("vulnerabilities", result)
        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["type"], "SQL Injection")
        
        # Verify call args (ensure it called the correct binary)
        args, _ = mock_run.call_args
        self.assertIn("/usr/local/bin/log_cruncher", args[0])

    @patch('subprocess.run')
    def test_go_scanner(self, mock_run):
        # Setup Mock
        mock_output = {
            "target": "example.com",
            "title": "Example Domain",
            "links": ["http://example.com/login"]
        }

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(mock_output)
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        # Execute
        scanner = GoScanner()
        result = self.loop.run_until_complete(scanner.scan("example.com"))

        # Assertions
        self.assertEqual(result["title"], "Example Domain")
        self.assertIn("http://example.com/login", result["links"])

        # Verify call
        args, _ = mock_run.call_args
        self.assertIn("/usr/local/bin/turboscan", args[0])

if __name__ == '__main__':
    unittest.main()
