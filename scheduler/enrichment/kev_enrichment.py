from scheduler.enrichment.base_enrichment import BaseEnrichmentJob

from collectors.kve_collector import KEVCollector


class KEVEnrichmentJob(BaseEnrichmentJob):
    source = "kev"

    def __init__(self):
        super().__init__()
        self.collector = KEVCollector()

    def enrich_record(self, record):
        print("KEV :", record["cve_id"])

        status = self.collector.is_known_exploited(record["cve_id"])

        return {
            "cve_id": record["cve_id"],
            "fields": {"kev_status": status, "kev_processed": True},
        }

    def fetch_by_id(self, cve_id):
        return self.is_known_exploited(cve_id)
