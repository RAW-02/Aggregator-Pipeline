import requests
from collectors.base_collector import BaseCollector

EPSS_URL = "https://api.first.org/data/v1/epss"

class EPSSCollector(BaseCollector):
    def fetch_by_id(self, cve_id: str):
        response = requests.get(EPSS_URL, params={"cve": cve_id}, timeout=30)

        response.raise_for_status()
        data = response.json()

        results = data.get("data", [])
        if not results:
            return {"epss_score": None}

        return {
            "epss_score": float(
                results[0].get("epss", 0)
            )
        }

    def get_epss_score(self, cve_id):
        return self.fetch_by_id(cve_id)["epss_score"]
    
    def fetch_incremental(self, last_sync):
        # EPSS publishes daily scores.
        # Future implementation:
        # Download daily CSV/API snapshot.
        return []
