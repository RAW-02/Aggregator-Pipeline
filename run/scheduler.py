from scheduler.enrichment.nvd_enrichment import NVDEnrichmentJob
from scheduler.enrichment.epss_enrichment import EPSSEnrichmentJob
from scheduler.enrichment.kev_enrichment import KEVEnrichmentJob
from scheduler.enrichment.exploitdb_enrichment import ExploitDBEnrichmentJob
from scheduler.enrichment.github_enrichment import GithubEnrichmentJob
from time import sleep

def main():
    jobs = [
        NVDEnrichmentJob(),
        EPSSEnrichmentJob(),
        KEVEnrichmentJob(),
        ExploitDBEnrichmentJob(),
        GithubEnrichmentJob()
    ]

    while True:
        for job in jobs:
            print(f"Running {job.source}")
            try:
                job.run(limit=100)
            except Exception as e:
                print(e)

        sleep(300)      # every 5 minutes


if __name__ == "__main__":
    main()