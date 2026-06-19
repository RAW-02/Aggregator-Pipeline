from scheduler.enrichment.base_enrichment import BaseEnrichmentJob

from pipeline.threat_score import ThreatScoreCalculator


class ThreatScoreEnrichmentJob(BaseEnrichmentJob):
    source = "threat"

    def enrich_record(self, record):
        print("THREAT :", record["cve_id"])

        score = ThreatScoreCalculator.calculate(record)

        return {
            "cve_id": record["cve_id"],
            "fields": {"threat_score": score, "threat_processed": True},
        }
