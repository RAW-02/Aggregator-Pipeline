import requests
from collectors.base_collector import BaseCollector
from normalizer.nvd_normalizer import NVDDataNormalizer
from datetime import datetime, UTC
from network.http_client import HttpClient
from network.retry import RetryManager
from network.rate_limiter import RateLimiter
import os

class NVDCollector(BaseCollector):
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    limiter = RateLimiter(0.5)

    def __init__(self):
        self.normalizer = NVDDataNormalizer()

    def fetch_by_id(self, cve_id):
        self.limiter.wait()
        def request():
            headers = {"User-Agent": "UniVulner"}
            
            api_key = os.getenv("NVD_API_KEY")
            if api_key:
                headers["apiKey"] = api_key
            
            response = HttpClient.session().get(self.NVD_BASE_URL, headers=headers, params={"cveId": cve_id}, timeout=int(os.getenv("NVD_TIMEOUT", 60)))
            response.raise_for_status()
            return response
        
        response = RetryManager.execute(request)
        if response is None:
            return None
        
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        return self.normalizer.get_result(
            vulnerabilities[0]
        )

    def get_nvd_by_cve(self, cve):
        result = self.fetch_by_id(cve)

        if result is None:
            return {
                "cvss_score": None,
                "severity": None,
                "cwe": [],
                "products": []
            }

        return {
            "cvss_score": result.cvss_score,
            "severity": result.severity,
            "cwe": result.cwe,
            "products": result.affected_products
        }

    def fetch_incremental(self, last_sync):
        if last_sync is None:
            return []

        self.limiter.wait()

        params={
            "lastModStartDate": last_sync,
            "lastModEndDate": datetime.now(UTC).isoformat().replace("+00:00", "Z")
        }
        headers = {"apiKey": os.getenv("NVD_API_KEY"), "User-Agent": "UniVulner"}

        response = RetryManager.execute(
            lambda:
            HttpClient.session().get(self.NVD_BASE_URL, headers=headers, params=params, timeout=60)
        )

        vulnerabilities = response.json().get("vulnerabilities", [])

        cves = []
        for item in vulnerabilities:
            cves.append(item["cve"]["id"])

        return cves