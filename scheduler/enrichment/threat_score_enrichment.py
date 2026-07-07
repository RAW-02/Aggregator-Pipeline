from scheduler.enrichment.base_enrichment import BaseEnrichmentJob
from pipeline.threat_score import ThreatScoreCalculator


class ThreatScoreEnrichmentJob(BaseEnrichmentJob):
    source = "threat"

    def get_records(self, limit):
        return self.repository.get_pending_threat(limit)

    def enrich_record(self, record):
        score = ThreatScoreCalculator.calculate(record)

        print(f"THREAT : {record['cve_id']} " f"-> {score}")

        return {
            "cve_id": record["cve_id"],
            "fields": {
                "threat_score": score,
                "threat_processed": True,
            },
        }
