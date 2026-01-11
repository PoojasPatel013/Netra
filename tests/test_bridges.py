import unittest
from unittest.mock import patch, MagicMock, AsyncMock
import asyncio
import json
import os
from netra.core.modules.rust_bridge import RustScanner
from netra.core.modules.go_bridge import GoScanner

class TestBridges(unittest.TestCase):
    
    def setUp(self):
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        self.loop.close()

    @patch('os.path.exists')
    @patch('subprocess.Popen')
    def test_rust_scanner(self, mock_popen, mock_exists):
        # Setup Mock
        mock_exists.return_value = True

        mock_output = {
            "total_lines": 5,
            "threats": [
                {"type": "SQL Injection", "line": 10, "content": "UNION SELECT"}
            ]
        }
        
        process_mock = MagicMock()
        process_mock.communicate.return_value = (json.dumps(mock_output), "")
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        # Execute
        scanner = RustScanner()
        # Since scan is async but uses sync Popen internally in this version
        result = self.loop.run_until_complete(scanner.scan("test_target"))

        # Assertions
        self.assertIn("findings", result)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["type"], "SQL Injection")
        
        # Verify call args
        args, _ = mock_popen.call_args
        self.assertIn("/app/bin/guard_bin", args[0])

    @patch('os.path.exists')
    @patch('asyncio.create_subprocess_exec')
    def test_go_scanner(self, mock_async_exec, mock_exists):
        # Setup Mock
        mock_exists.return_value = True

        mock_output = {
            "target": "example.com",
            "title": "Example Domain",
            "links": ["http://example.com/login"]
        }

        # Mock the async process
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (json.dumps(mock_output).encode(), "".encode())
        process_mock.returncode = 0
        mock_async_exec.return_value = process_mock

        # Execute
        scanner = GoScanner()
        result = self.loop.run_until_complete(scanner.scan("example.com"))

        # Assertions
        self.assertEqual(result["title"], "Example Domain")
        self.assertIn("http://example.com/login", result["links"])

        # Verify call
        args, _ = mock_async_exec.call_args
        self.assertIn("/app/bin/scout_bin", args)

    @patch('os.path.exists')
    @patch('asyncio.create_subprocess_exec')
    def test_ghost_scanner(self, mock_async_exec, mock_exists):
        from netra.core.modules.cpp_bridge import GhostScanner
        
        # Setup Mock
        mock_exists.return_value = True

        mock_output = {
            "agent": "VortexAgent",
            "os": "Linux",
            "user": "root",
            "processes": [{"pid": 1, "name": "init"}]
        }

        # Mock the async process
        process_mock = AsyncMock()
        process_mock.communicate.return_value = (json.dumps(mock_output).encode(), "".encode())
        process_mock.returncode = 0
        mock_async_exec.return_value = process_mock

        # Execute
        scanner = GhostScanner()
        result = self.loop.run_until_complete(scanner.scan("127.0.0.1"))

        # Assertions
        self.assertEqual(result["status"], "completed")
        findings = result["findings"][0]
        self.assertIn("Linux", findings["description"])
        self.assertEqual(len(findings["data"]), 1)

if __name__ == '__main__':
    unittest.main()
