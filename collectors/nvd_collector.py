import requests

class NVDCollector:
    NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch_NVD_data(self, keyword: str, results_per_page: int = 7):
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