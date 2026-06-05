import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class KEVLookup:
    def __init__(self):
        self.catalog = None

    def load_catalog(self):
        if self.catalog:
            return self.catalog

        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()

        self.catalog = response.json()
        return self.catalog

    def is_known_exploited(self, cve_id: str) -> bool:
        catalog = self.load_catalog()
        vulnerabilities = catalog.get("vulnerabilities",[])

        for vuln in vulnerabilities:
            if vuln.get("cveID") == cve_id:
                return True

        return False