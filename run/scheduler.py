from scheduler.enrichment.nvd_enrichment import NVDEnrichmentJob
from scheduler.enrichment.epss_enrichment import EPSSEnrichmentJob
from scheduler.enrichment.kev_enrichment import KEVEnrichmentJob
from scheduler.enrichment.exploitdb_enrichment import ExploitDBEnrichmentJob
from scheduler.enrichment.github_enrichment import GithubEnrichmentJob
from scheduler.enrichment.threat_score_enrichment import ThreatScoreEnrichmentJob
from config.settings import ENRICHMENT_LIMIT, ENRICHMENT_INTERVAL
from time import sleep

def main():
    jobs = [
        NVDEnrichmentJob(),
        EPSSEnrichmentJob(),
        KEVEnrichmentJob(),
        ExploitDBEnrichmentJob(),
        GithubEnrichmentJob(),
        ThreatScoreEnrichmentJob()
    ]

    while True:
        for job in jobs:
            print()
            print("=" * 60)
            print(f"Running {job.source.upper()} Enrichment")
            print("=" * 60)
            
            try:
                job.run(limit=ENRICHMENT_LIMIT)
            except Exception as e:
                print(e)

        sleep(ENRICHMENT_INTERVAL)      # every 5 minutes


if __name__ == "__main__":
    main()