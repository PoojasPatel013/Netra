import pytest
import re
from aioresponses import aioresponses
from netra.core.modules.cloud import CloudScanner
from netra.core.modules.graphql import GraphQLScanner
from netra.core.http import SafeHTTPClient

@pytest.mark.asyncio
async def test_cloud_scanner_found():
    scanner = CloudScanner()
    target = "example"
    url = f"https://{target}.s3.amazonaws.com"
    
    with aioresponses() as m:
        m.head(url, status=200)
        # Mock other potential buckets to avoid lookup errors if code checks them
        m.head(re.compile(r'https://.*\.s3\.amazonaws\.com'), status=404)
        
        results = await scanner.scan(target)
        
        found = False
        for bucket in results["s3_buckets"]:
             if bucket["url"] == url and bucket["code"] == 200:
                 found = True
        
        assert found

@pytest.mark.asyncio
async def test_graphql_scanner_introspection():
    scanner = GraphQLScanner()
    target = "http://example.com"
    url = "http://example.com/graphql"
    
    with aioresponses() as m:
        # 1. Endpoint Check
        m.post(url, status=200, payload={"data": {}})
        
        # 2. Introspection Check
        introspection_payload = {"data": {"__schema": {"types": [{"name": "User"}]}}}
        m.post(url, status=200, payload=introspection_payload)
        
        results = await scanner.scan(target)
        
        assert results["introspection_enabled"] is True
        assert len(results["vulnerabilities"]) >= 1
        assert results["vulnerabilities"][0]["type"] == "GraphQL Introspection"

@pytest.mark.asyncio
async def test_safe_http_rate_limiting():
    # Test that client retries on 429
    url = "http://example.com/api"
    
    with aioresponses() as m:
        # First attempt: 429
        m.get(url, status=429)
        # Second attempt: 200 OK
        m.get(url, status=200, body="Success")
        
        async with SafeHTTPClient() as client:
            # We expect a delay here, but asyncio.sleep in tests is fast/mocked if using proper tools, 
            # here we just check logic flow.
            # SafeHTTPClient uses base_delay=1.0. 
            # We don't want to wait 1s in tests usually, but for simple integration test we accept it.
            response = await client.get(url)
            assert response.status == 200
            txt = await response.text()
            assert txt == "Success"
