from scheduler.enrichment.nvd_enrichment import NVDEnrichmentJob
from scheduler.enrichment.epss_enrichment import EPSSEnrichmentJob
from scheduler.enrichment.kev_enrichment import KEVEnrichmentJob
from scheduler.enrichment.exploitdb_enrichment import ExploitDBEnrichmentJob
from scheduler.enrichment.github_enrichment import GithubEnrichmentJob


def main():

    jobs = [

        NVDEnrichmentJob(),

        EPSSEnrichmentJob(),

        KEVEnrichmentJob(),

        ExploitDBEnrichmentJob(),

        GithubEnrichmentJob()

    ]

    for job in jobs:

        print()
        print("=" * 60)
        print(f"Running {job.source.upper()} enrichment")
        print("=" * 60)

        job.run(limit=100)


if __name__ == "__main__":

    main()