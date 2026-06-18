from scheduler.enrichment.threat_score_enrichment import ThreatScoreEnrichmentJob

job = ThreatScoreEnrichmentJob()

job.run(limit=10)