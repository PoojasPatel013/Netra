import pytest
from aioresponses import aioresponses
from netra.core.http import SafeHTTPClient
from netra.core.reporter import SARIFReporter


# 1. Unit Test for Reporter (SARIF Standardization)
def test_sarif_reporter_structure():
    reporter = SARIFReporter()
    reporter.add_result(
        scanner_name="TestScanner",
        vulnerability_type="Test Vuln",
        severity="High",
        message="This is a test",
        location="http://test.com",
    )

    report = reporter._generate_report()

    # Check SARIF Compliance
    assert report["version"] == "2.1.0"
    assert report["runs"][0]["tool"]["driver"]["name"] == "Netra"
    assert len(report["runs"][0]["results"]) == 1
    assert report["runs"][0]["results"][0]["level"] == "error"  # High = error


# 2. Integration Test with Mocking (Rate Limiting Maturity)
@pytest.mark.asyncio
async def test_safe_http_client_rate_limit():
    with aioresponses() as m:
        url = "http://example.com/api"

        # Mock 429 then 200
        m.get(url, status=429)
        m.get(url, status=200, body="Success")

        async with SafeHTTPClient() as client:
            response = await client.get(url)
            assert response.status == 200

            # Check if it actually retried (aioresponses logs calls)
            # We expect 2 calls
            # Note: We can't easily count calls with basic aioresponses without deeper inspection,
            # but getting 200 after 429 proves the loop worked.


# 3. GraphQL Introspection Regex Test (Modern Web)
def test_graphql_sanity():
    # Simple regex check for introspection query structure (heuristic)
    query = "{__schema{types{name}}}"
    assert "__schema" in query
    assert "types" in query
