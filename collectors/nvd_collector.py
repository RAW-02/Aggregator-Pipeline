import requests

from normalizer.nvd_normalizer import NVDDataNormalizer

class NVDCollector:
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_NVD_data(self, keyword: str, results_per_page: int = 20):
        response = requests.get(
            self.NVD_BASE_URL,
            params={
                "keywordSearch": keyword,
                "resultsPerPage": results_per_page
            },
            timeout=30
        )

        response.raise_for_status()
        return response.json()
    
    def get_nvd_by_cve(self, cve_id):
        print("NVD Data Collecting .......")
        response = requests.get(self.NVD_BASE_URL, params={"cveId": cve_id}, timeout=30)
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities",[])

        if not vulnerabilities:
            return {
                "cvss_score": None,
                "severity": None,
                "cwe": [],
                "products": []
            }

        normalizer = NVDDataNormalizer()
        result = normalizer.get_result(vulnerabilities[0])

        return {
            "cvss_score": result.cvss_score,
            "severity": result.severity,
            "cwe": result.cwe,
            "products": result.affected_products
        }