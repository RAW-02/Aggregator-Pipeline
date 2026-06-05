import requests
import re

MITRE_API_URL = "https://cveawg.mitre.org/api/cve/"
CVE_PATTERN = r"^CVE-\d{4}-\d+$"

input = "CVE-2021-44228"

class MITRECollector:
    def __init__(self, timeout=15):
        self.timeout = timeout

    def fetch_cve(self, cve_id: str) -> dict:
        url = f"{MITRE_API_URL}{cve_id}"

        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        raw_data = response.json()

        return self._normalize(raw_data)

    def _normalize(self, raw_data: dict) -> dict:
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
    

def validate_cve(cve_id):
    return bool(re.match(CVE_PATTERN, cve_id))

if not validate_cve(input):
    raise ValueError("Invalid CVE format")