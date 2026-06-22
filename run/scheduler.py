from scheduler.enrichment.nvd_enrichment import NVDEnrichmentJob  # noqa: F401
from scheduler.enrichment.epss_enrichment import EPSSEnrichmentJob
from scheduler.enrichment.kev_enrichment import KEVEnrichmentJob  # noqa: F401
from scheduler.enrichment.exploitdb_enrichment import (  # noqa: F401, E501
    ExploitDBEnrichmentJob,
)  # noqa: F401, E501
from scheduler.enrichment.github_enrichment import GithubEnrichmentJob  # noqa: F401
from scheduler.enrichment.threat_score_enrichment import (  # noqa: F401, E501
    ThreatScoreEnrichmentJob,
)  # noqa: F401, E501
from config.settings import ENRICHMENT_LIMIT, ENRICHMENT_INTERVAL
from time import sleep


def main():
    jobs = [
        EPSSEnrichmentJob(),
        # NVDEnrichmentJob(),
        KEVEnrichmentJob(),
        # ExploitDBEnrichmentJob(),
        # GithubEnrichmentJob(),
        # ThreatScoreEnrichmentJob(),
    ]

    while True:
        for job in jobs:
            print()
            print("=" * 60)
            print(f"Running {job.source.upper()} Enrichment")
            print("=" * 60)

            try:
                updated = job.run(limit=ENRICHMENT_LIMIT)

                if updated == 0:
                    print()
                    print(f"{job.source.upper()} COMPLETED")
                    continue

            except Exception as e:
                print(e)

        sleep(ENRICHMENT_INTERVAL)


if __name__ == "__main__":
    main()
