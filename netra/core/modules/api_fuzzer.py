import logging
import json
import asyncio
from typing import Dict, Any, List
from netra.core.scanner import BaseScanner
from netra.core.http import SafeHTTPClient

logger = logging.getLogger("netra.core.api")

class ZombieScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        API Security: Detects OpenAPI/Swagger, Shadow APIs, and Zombie Versions.
        """
        results = {
            "swagger_detected": False,
            "endpoints_fuzzed": 0,
            "vulnerabilities": []
        }
        
        target = target if target.startswith("http") else f"http://{target}"
        base_url = target.rstrip("/")
        
        # 0. Zombie Version Check (Deprecated APIs)
        await self._check_deprecated_versions(base_url, results)
        
        # 1. Discovery: Check common Swagger locations
        swagger_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api/docs",
            "/v2/api-docs",
            "/api/swagger.json"
        ]
        
        found_schema = None
        
        async with SafeHTTPClient() as client:
            for path in swagger_paths:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url, timeout=5)
                    if resp.status == 200:
                        try:
                            # Try parsing as JSON
                            schema = await resp.json()
                            if "swagger" in schema or "openapi" in schema:
                                found_schema = schema
                                results["swagger_detected"] = True
                                results["schema_url"] = url
                                logger.info(f"Found Swagger schema at {url}")
                                break
                        except:
                            pass
                except Exception:
                    continue
            
            # 2. Fuzzing (if schema found)
            if found_schema:
                await self._fuzz_schema(found_schema, base_url, client, results)
            
            # 3. Shadow API Detection (Zombie APIs)
            # Scan JS files for endpoints NOT in the schema
            await self._find_shadow_apis(base_url, client, results, found_schema)
                
        return results

    async def _check_deprecated_versions(self, base_url: str, results: Dict):
        """
        Checks for Zombie API versions (e.g., /v1/ if /v2/ is present).
        """
        import re
        # Heuristic: guess current version from URL or just try common ones
        versions = ["v1", "v2", "v3", "api/v1", "api/v2"]
        
        async with SafeHTTPClient() as client:
            for v in versions:
                # If the base URL doesn't already contain this version
                if f"/{v}" not in base_url:
                     try:
                         # Probe for root of version
                         test_url = f"{base_url}/{v}/"
                         resp = await client.get(test_url, timeout=5)
                         # 200 or 401/403 often means it exists
                         if resp.status in [200, 401, 403]:
                             results["vulnerabilities"].append({
                                 "type": "Zombie API Version Detected",
                                 "severity": "High",
                                 "endpoint": test_url,
                                 "details": f"Found potentially deprecated API version '{v}' which is still active.",
                                 "evidence": f"Status: {resp.status}"
                             })
                     except:
                         pass

    async def _find_shadow_apis(self, base_url: str, client: SafeHTTPClient, results: Dict, schema: Dict = None):
        import re
        from netra.ml.zombie_hunter import ZombieHunter
        
        known_paths = set()
        if schema:
            known_paths = set(schema.get("paths", {}).keys())
            
        logger.info(f"Scanning for Shadow APIs on {base_url}")
        try:
            # Fetch Index
            resp = await client.get(base_url, timeout=10)
            if resp.status != 200: return
            html = await resp.text()
            
            # Extract JS links
            js_links = re.findall(r'src=["\'](.*?\.js)["\']', html)
            
            for link in js_links[:5]: # Limit 5
                if not link.startswith("http"):
                     link = f"{base_url.rstrip('/')}/{link.lstrip('/')}"
                
                try:
                    js_resp = await client.get(link, timeout=5)
                    if js_resp.status == 200:
                        js_code = await js_resp.text()
                        
                        # 1. Broad String Extraction (Capture everything that looks like a string)
                        # We use the ML model to filter "noise" from "signals"
                        candidates = re.findall(r'["\'](/[^"\'\s]+)["\']', js_code)
                        
                        unique_candidates = set(candidates)
                        
                        for candidate in unique_candidates:
                             # 2. ASK THE NEURAL ENGINE (TinyLLM)
                             is_api = ZombieHunter.predict_is_api(candidate)
                             
                             if is_api:
                                 # Normalize
                                 if candidate not in known_paths:
                                     results["vulnerabilities"].append({
                                         "type": "Shadow API (Zombie Endpoint)",
                                         "severity": "High",
                                         "endpoint": f"{link} -> {candidate}",
                                         "details": f"ML Model identified '{candidate}' as a hidden API endpoint (Score > 0.8)",
                                         "evidence": f"Candidate: {candidate}"
                                     })
                except Exception:
                    pass
        except Exception:
            pass

    async def _fuzz_schema(self, schema: Dict, base_url: str, client: SafeHTTPClient, results: Dict):
        paths = schema.get("paths", {})
        
        fuzz_tasks = []
        
        for path, methods in paths.items():
            for method_name, details in methods.items():
                if method_name.upper() not in ["GET", "POST", "PUT", "DELETE"]:
                    continue
                
                # Construct Fuzz URL
                # Replace {id} with test IDs for BOLA check
                # 1. Sequential ID Fuzzing (1, 2, 1000)
                fuzzed_path = path.replace("{id}", "1").replace("{userId}", "1")
                
                # 2. Error Handling Check (Big Int)
                err_path = path.replace("{id}", "999999").replace("{userId}", "999999")
                
                url = f"{base_url}{fuzzed_path}"
                
                # Check 1: ID Enumeration / Access Check
                fuzz_tasks.append(self._check_endpoint(client, method_name, url, "BOLA/ID Check", results))
                
                # Check 2: Error Handling / Info Leak
                if err_path != fuzzed_path:
                     err_url = f"{base_url}{err_path}"
                     fuzz_tasks.append(self._check_endpoint(client, method_name, err_url, "Error Handling", results))

                results["endpoints_fuzzed"] += 1
                if results["endpoints_fuzzed"] > 20: # Cap at 20 endpoints to avoid excessive traffic
                     break
            if results["endpoints_fuzzed"] > 20:
                break
                
        await asyncio.gather(*fuzz_tasks)

    async def _check_endpoint(self, client, method, url, check_type, results):
        try:
            resp = await client.request(method, url, timeout=5)
            
            # Simple Heuristics
            if resp.status == 500:
                 results["vulnerabilities"].append({
                     "type": "API Server Error (Potential DoS)",
                     "severity": "Medium",
                     "endpoint": f"{method} {url}",
                     "details": "Server returned 500 Internal Server Error. Input validation might be missing."
                 })
            elif resp.status == 200 and "BOLA" in check_type:
                 # If we accessed ID 1 without auth, it's interesting (oversimplified BOLA check)
                 # Real BOLA requires auth context, but this proves the endpoint is reachable.
                 results["vulnerabilities"].append({
                     "type": "Possible BOLA / ID Enumeration",
                     "severity": "High", 
                     "endpoint": f"{method} {url}",
                     "details": "Endpoint accepted ID '1' and returned 200 OK. Verify authorization logic.",
                     "evidence": f"Status: {resp.status}"
                 })
                 
        except Exception as e:
            pass
