from concurrent.futures import ThreadPoolExecutor

from scheduler.enrichment.base_enrichment import BaseEnrichmentJob
from collectors.nvd_collector import NVDCollector
from config.settings import NVD_THREAD_POOL_SIZE


class NVDEnrichmentJob(BaseEnrichmentJob):
    source = "nvd"

    def __init__(self):
        super().__init__()
        self.collector = NVDCollector()

    def get_records(self, limit):
        return self.repository.get_pending_nvd(limit)

    def enrich_record(self, record):
        print("NVD :", record["cve_id"])
        result = self.collector.get_nvd_by_cve(record["cve_id"])

        if result is None:
            return None

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

    def run(self, limit=100):
        records = self.get_records(limit)
        print("NVD Pending :", len(records))

        if not records:
            return 0

        with ThreadPoolExecutor(max_workers=NVD_THREAD_POOL_SIZE) as executor:
            results = list(executor.map(self.safe_enrich, records))

        updates = [r for r in results if r]
        self.repository.bulk_update(updates)

        print()
        print("Updated :", len(updates))

        return len(updates)
