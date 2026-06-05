import requests

EPSS_URL = "https://api.first.org/data/v1/epss"

class EPSSLookup:
    def get_epss_score(self, cve_id: str):
        response = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=30)
        response.raise_for_status()

        data = response.json()
        results = data.get("data", [])

        if not results:
            return None

        epss = float(results[0].get("epss", 0))
        return epss