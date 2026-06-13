from collectors.nvd_collector import NVDCollector
from storage.json_repo import JsonRepository

class NVDEnrichmentPipeline:
    def __init__(self):
        self.nvd = NVDCollector()
        self.repository = JsonRepository()

    def enrich(self, record):
        cve = record["cve_id"]
        print("NVD Enriching :", cve)

        try:
            nvd = self.nvd.get_nvd_by_cve(cve)
            updates = {
                "cvss_score": nvd["cvss_score"],
                "severity": nvd["severity"],
                "cwe": nvd["cwe"],
                "products": nvd["products"],
                "nvd_processed": True
            }

            self.repository.update(cve, updates)
            return True

        except Exception as e:
            print(e)
            return False