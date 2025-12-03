import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from vortex.core.modules.network import PortScanner
from vortex.core.modules.http import HTTPScanner

@pytest.mark.asyncio
async def test_port_scanner_open():
    scanner = PortScanner(ports=[80])
    
    # Mock asyncio.open_connection to succeed
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_conn.return_value = (mock_reader, mock_writer)
        
        results = await scanner.scan("example.com")
        assert 80 in results["open_ports"]

@pytest.mark.asyncio
async def test_http_scanner_success():
    scanner = HTTPScanner()
    
    # Mock aiohttp.ClientSession
    with patch("aiohttp.ClientSession") as mock_session_cls:
        mock_session = AsyncMock()
        mock_session_cls.return_value.__aenter__.return_value = mock_session
        
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Server": "TestServer", "X-Powered-By": "Python"}
        mock_resp.__aenter__.return_value = mock_resp
        
        mock_session.get.return_value = mock_resp
        
        results = await scanner.scan("http://example.com")
        assert results["status_code"] == 200
        assert results["server"] == "TestServer"
        assert "Python" in results["tech_stack"]

