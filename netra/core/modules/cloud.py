import aiohttp
import logging
from typing import Dict, Any
from netra.core.scanner import BaseScanner
from netra.core.http import SafeHTTPClient

logger = logging.getLogger("netra.core.cloud")


class CloudScanner(BaseScanner):
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Checks for public S3 buckets associated with the target name.
        """
        results = {"s3_buckets": []}

        # Simple heuristic: check if target name is a bucket
        bucket_names = [
            target,
            f"www.{target}",
            f"{target}-backup",
            f"{target}-dev",
            f"{target}-assets",
        ]

        base_name = target.split(".")[0]
        if base_name != target:
            bucket_names.append(base_name)
            bucket_names.append(f"{base_name}-assets")
            bucket_names.append(f"{base_name}-backup")

        async with SafeHTTPClient() as client:
            for bucket in set(bucket_names):
                # 1. AWS S3
                s3_url = f"https://{bucket}.s3.amazonaws.com"
                await self._check_bucket(client, bucket, s3_url, "AWS S3", results)

                # 2. Azure Blob (commonly 'container' but account name is the bucket check equivalent)
                # https://<account>.blob.core.windows.net/
                azure_url = f"https://{bucket}.blob.core.windows.net/"
                await self._check_bucket(
                    client, bucket, azure_url, "Azure Blob", results
                )

                # 3. GCP Storage
                gcp_url = f"https://storage.googleapis.com/{bucket}"
                await self._check_bucket(client, bucket, gcp_url, "GCP Bucket", results)

        return results

    async def _check_bucket(self, client, name, url, provider, results):
        try:
            response = await client.head(url, timeout=3)
            if response.status == 200:
                results["s3_buckets"].append(
                    {
                        "bucket": name,
                        "url": url,
                        "provider": provider,
                        "status": "Publicly Listable (Dangerous)",
                        "code": 200,
                    }
                )
            elif response.status == 403:
                results["s3_buckets"].append(
                    {
                        "bucket": name,
                        "url": url,
                        "provider": provider,
                        "status": "Exists but Private (Info)",
                        "code": 403,
                    }
                )
            elif response.status == 404:
                pass  # Not found
            elif response.status == 400 and provider == "Azure Blob":
                # Azure returns 400 for Invalid Query Parameter usually, but 404 if account doesn't exist
                # Sometimes 404 means container not found but account exists.
                # For account enumeration, we look for DNS resolution usually, but HTTP 400/403 implies existence.
                pass
        except Exception:
            pass
