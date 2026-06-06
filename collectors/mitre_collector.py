import requests
import re

MITRE_API_URL = "https://cveawg.mitre.org/api/cve/"
CVE_PATTERN = r"^CVE-\d{4}-\d+$"

class MITRECollector:
    def __init__(self, timeout=15):
        self.timeout = timeout

    @staticmethod
    def validate_cve(cve_id):
        return bool(re.match(CVE_PATTERN, cve_id))

    def fetch_CVE_MITRE(self, cve_id: str) -> dict:
        if not MITRECollector.validate_cve(cve_id):
            raise ValueError("Invalid CVE format")
    
        url = f"{MITRE_API_URL}{cve_id}"

        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        raw_data = response.json()

        return raw_data

    def search_mitre_record_by_cve(self, raw_data: dict) -> dict:
        metadata = raw_data.get("cveMetadata", {})
        cna = (raw_data.get("containers", {}).get("cna", {}))
        description = ""
        descriptions = cna.get("descriptions", [])

        if descriptions:
            description = descriptions[0].get("value", "")

        references = []
        for ref in cna.get("references", []):
            url = ref.get("url")
            if url:
                references.append(url)
        
        references = references[:3]

        normalized = {
            "cve_id": metadata.get("cveId"),
            "description": description,
            "published_date": metadata.get("datePublished").split("T")[0],
            "last_modified": metadata.get("dateUpdated").split("T")[0],
            "references": references
        }
        
        return normalized
    
    def get_mitre_result(self, cve_id: str) -> dict:
        raw_data = self.fetch_CVE_MITRE(cve_id)
        return self.search_mitre_record_by_cve(raw_data)