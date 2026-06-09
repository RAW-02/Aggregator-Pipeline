from collectors.base_collector import BaseCollector
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class KEVCollector(BaseCollector):
    def __init__(self):
        self.catalog = None

    def load_catalog(self):
        if self.catalog:
            return self.catalog

        response = requests.get(KEV_URL, timeout=30)
        response.raise_for_status()

        self.catalog = response.json()
        return self.catalog

    def fetch_by_id(self, cve):
        catalog = self.load_catalog()
        vulnerabilities = catalog.get("vulnerabilities", [])
        for item in vulnerabilities:
            if item.get("cveID") == cve:
                return {"kev_status": True}

        return {"kev_status": False}

    def is_known_exploited(self, cve):
        return self.fetch_by_id(cve)["kev_status"]
    
    def fetch_incremental(self, last_sync):
        # Future implementation
        return []


# ------------------------------------------------------------------------------------------
# Code Before BaseCollector
# class KEVLookup:
#     def __init__(self):
#         self.catalog = None

#     def load_catalog(self):
#         if self.catalog:
#             return self.catalog

#         response = requests.get(KEV_URL, timeout=30)
#         response.raise_for_status()

#         self.catalog = response.json()
#         return self.catalog

#     def is_known_exploited(self, cve_id: str) -> bool:
#         catalog = self.load_catalog()
#         vulnerabilities = catalog.get("vulnerabilities",[])

#         for vuln in vulnerabilities:
#             if vuln.get("cveID") == cve_id:
#                 return True

#         return False