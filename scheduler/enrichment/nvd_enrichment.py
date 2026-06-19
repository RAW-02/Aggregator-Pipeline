from scheduler.enrichment.base_enrichment import BaseEnrichmentJob

from collectors.nvd_collector import NVDCollector


class NVDEnrichmentJob(BaseEnrichmentJob):
    source = "nvd"

    def __init__(self):
        super().__init__()
        self.collector = NVDCollector()

    def enrich_record(self, record):
        print("NVD :", record["cve_id"])

        result = self.collector.get_nvd_by_cve(record["cve_id"])

        return {
            "cve_id": record["cve_id"],
            "fields": {
                "cvss_score": result["cvss_score"],
                "severity": result["severity"],
                "cwe": result["cwe"],
                "products": result["products"],
                "nvd_processed": True,
            },
        }
